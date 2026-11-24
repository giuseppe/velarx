-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proof of `AGroupIsHeldForTheNewLayersThatNeedIt` (Spec.lean).  When
-- `step` is told `Prepared` by a pull that is preparing, each group of the event is held (with
-- the layers that are new among those it is for) if a new layer waits for it, and is told back
-- (`Forget`), and not held, if none does.
--
-- Why it is needed: `ALayerIsCommittedAfterItsGroups` says every group that names a layer is
-- done; it is as good as the core's knowledge of the groups.  A `prepared` that dropped a group
-- a new layer waits for (an earlier bug) makes that claim true of no group at all.  This is the
-- link that says the core knows the group.
--
-- The argument follows the Rust, from the inside out:
--   1. The pull is found and is preparing, so `prepared` takes the branch of an answer in time
--      (`filter_keeps_preparing`), and the layers it takes as new are those of the event that the
--      table lacks (`fresh_layers`).
--   2. For each group of the event, the loop `prepared_loop2` keeps the layers the group is for
--      that are new (`keep_fresh`): if none is left it asks for `Forget`, else it pushes a group of
--      that name with those layers (`prepared_loop2_holds`).
--   3. `advance` then changes only the state of a group (`advance_keeps_pulls`, `groupKey`) and
--      only adds to the actions, so what was held or asked stays so.
--   4. The names of the groups the event lists are distinct from each other and from those of the
--      core (`WellTold`), so a group that was told back has no namesake in the table.
--
-- Read before this file: Pulls.lean, Verdict.lean, and the statement in Spec.lean.
--
-- Notation: `Ok m P` is "if `m` returns, its result satisfies `P`"; `l.filter keep` is the
-- elements of `l` that `keep` says yes to; `r.1`, `r.2` are the first and second element of a pair.
import LazyCore.Sharers

open Aeneas Aeneas.Std Result velarx_lazy_core

namespace LazyCore

/-- `prepared` keeps of the layers a group is for (`needed_by.retain(|l| fresh.contains(l))`) those
that are in `fresh`. -/
theorem keep_fresh (fresh needed_by : alloc.vec.Vec Std.U32) :
    Ok (alloc.vec.Vec.retain alloc.alloc.Global
      prepared.closure_2.Insts.CoreOpsFunctionFnMutTupleShared1U32Bool needed_by fresh)
      (fun w => w.val = needed_by.val.filter fun l => decide (l ∈ fresh.val)) := by
  have answers : ∀ l : Std.U32,
      prepared.closure_2.Insts.CoreOpsFunctionFnMutTupleShared1U32Bool.call_mut fresh l =
        ok (decide (l ∈ fresh.val), fresh) := by
    intro l
    have contains := anyM_pure (core.cmp.PartialEqU32.eq l) (fun y => l = y)
      (fun x => rfl) (alloc.vec.Vec.deref fresh).val
    simp only [prepared.closure_2.Insts.CoreOpsFunctionFnMutTupleShared1U32Bool.call_mut,
      core.slice.Slice.contains, contains, bind_ok]
    simp [alloc.vec.Vec.deref]
  exact retain_filter alloc.alloc.Global
    prepared.closure_2.Insts.CoreOpsFunctionFnMutTupleShared1U32Bool _ fresh answers needed_by

/-- The loop of `prepared` over the groups of an answer in time (`for g in groups`), given the
layers `F` that are new (`fresh` is the vector of them).  It appends to the table groups `new`, and
to `out` the actions `t`, such that for each group `g` of the event: if a new layer waits for it,
`new` has a group of its name, for the layers of `g` that are new and only those; if none does, `t`
tells it back (`Forget`).  The names of `new` are some of those of the event, in order, each of a
group a new layer waits for (Tables.lean takes the order, for the names of the groups). -/
theorem prepared_loop2_holds (F : Std.U32 → Prop) (iter : alloc.vec.into_iter.IntoIter GroupFact)
    (v : alloc.vec.Vec Group) (out : alloc.vec.Vec Action) (fresh : alloc.vec.Vec Std.U32)
    (is_fresh : ∀ l, l ∈ fresh.val ↔ F l) :
    Ok (prepared_loop2 iter v out fresh) (fun r => ∃ (new : List Group) (t : List Action),
      r.1.val = v.val ++ new ∧ r.2.val = out.val ++ t ∧
      (new.map (·.id)).Sublist (iter.val.map (·.id)) ∧
      (∀ x ∈ new, ∃ g ∈ iter.val, x.id = g.id ∧ ∃ l ∈ g.needed_by.val, F l) ∧
      ∀ g ∈ iter.val,
        ((∃ l ∈ g.needed_by.val, F l) → ∃ x ∈ new, x.id = g.id ∧
          ∀ l, l ∈ x.needed_by.val ↔ l ∈ g.needed_by.val ∧ F l) ∧
        ((¬ ∃ l ∈ g.needed_by.val, F l) → Action.Forget (Work.Group g.id) ∈ t)) := by
  unfold prepared_loop2
  -- `done` is the groups of the event the loop went through, `new` the groups it pushed and `t`
  -- the actions it pushed
  refine Ok.loop (I := fun x => ∃ (done : List GroupFact) (new : List Group) (t : List Action),
    iter.val = done ++ x.1.val ∧ x.2.1.val = v.val ++ new ∧ x.2.2.val = out.val ++ t ∧
    (new.map (·.id)).Sublist (done.map (·.id)) ∧
    (∀ y ∈ new, ∃ g ∈ done, y.id = g.id ∧ ∃ l ∈ g.needed_by.val, F l) ∧
    ∀ g ∈ done,
      ((∃ l ∈ g.needed_by.val, F l) → ∃ y ∈ new, y.id = g.id ∧
        ∀ l, l ∈ y.needed_by.val ↔ l ∈ g.needed_by.val ∧ F l) ∧
      ((¬ ∃ l ∈ g.needed_by.val, F l) → Action.Forget (Work.Group g.id) ∈ t)) ?_
    ⟨[], [], [], by simp, by simp, by simp, by simp, by simp, by simp⟩
  rintro ⟨it, v1, out1⟩ ⟨done, new, t, split, pushed, pushed_out, sub, from_told, told⟩
  dsimp only at split pushed pushed_out
  unfold prepared_loop2.body
  refine Ok.bind (into_iter_next _) ?_
  rintro ⟨o, it1⟩ (⟨rfl, ended⟩ | ⟨gf, rest, rfl, cons, is_rest⟩)
  · -- no group is left
    have all_done : iter.val = done := by simp [split, ended]
    rw [all_done]
    exact Ok.ok.mpr ⟨new, t, pushed, pushed_out, sub, from_told, told⟩
  -- the layers of the group that are new
  refine Ok.bind (keep_fresh fresh gf.needed_by) ?_; intro needed_by is_needed_by
  have in_needed_by : ∀ l, l ∈ needed_by.val ↔ l ∈ gf.needed_by.val ∧ F l := by
    intro l; simp [is_needed_by, is_fresh]
  have split1 : iter.val = (done ++ [gf]) ++ it1.val := by simp [split, cons, is_rest]
  have is_empty : alloc.vec.Vec.is_empty needed_by = ok (decide (needed_by.val = [])) := by
    simp [alloc.vec.Vec.is_empty, alloc.vec.Vec.length]
  rw [is_empty]; simp only [bind_ok]
  by_cases waited : ∃ l ∈ gf.needed_by.val, F l
  · -- a new layer waits for it: it is pushed
    have not_empty : needed_by.val ≠ [] := by
      obtain ⟨l, in_gf, new_l⟩ := waited
      exact List.ne_nil_of_mem ((in_needed_by l).mpr ⟨in_gf, new_l⟩)
    simp only [not_empty, decide_false, Bool.false_eq_true, ↓reduceIte]
    refine Ok.bind (push_appends _ _) ?_; intro v2 pushed2
    refine Ok.ok.mpr ⟨done ++ [gf], new ++ [⟨gf.id, GroupState.Todo, needed_by⟩], t, split1,
      by rw [pushed2, pushed]; simp, pushed_out, by simpa using sub, ?_, ?_⟩
    · intro y in_y
      rcases List.mem_append.mp in_y with old | here
      · obtain ⟨g, in_g, same, named⟩ := from_told y old
        exact ⟨g, List.mem_append_left _ in_g, same, named⟩
      · exact ⟨gf, by simp, by simp [List.mem_singleton.mp here], waited⟩
    · intro g in_g
      rcases List.mem_append.mp in_g with old | here
      · obtain ⟨kept, forgotten⟩ := told g old
        refine ⟨fun w => ?_, forgotten⟩
        obtain ⟨y, in_y, rest⟩ := kept w
        exact ⟨y, List.mem_append_left _ in_y, rest⟩
      · have : g = gf := by simpa using here
        subst this
        exact ⟨fun _ => ⟨⟨g.id, GroupState.Todo, needed_by⟩, by simp, rfl, in_needed_by⟩,
          fun not_waited => absurd waited not_waited⟩
  · -- no new layer waits for it: it is told back
    have is_empty' : needed_by.val = [] := by
      apply List.eq_nil_iff_forall_not_mem.mpr
      intro l in_l
      exact waited ⟨l, ((in_needed_by l).mp in_l).1, ((in_needed_by l).mp in_l).2⟩
    simp only [is_empty', decide_true, ↓reduceIte]
    refine Ok.bind (push_appends _ _) ?_; intro out2 pushed2
    refine Ok.ok.mpr ⟨done ++ [gf], new, t ++ [Action.Forget (Work.Group gf.id)], split1, pushed,
      by rw [pushed2, pushed_out]; simp, sub.trans (by simp), ?_, ?_⟩
    · intro y in_y
      obtain ⟨g, in_g, same, named⟩ := from_told y in_y
      exact ⟨g, List.mem_append_left _ in_g, same, named⟩
    · intro g in_g
      rcases List.mem_append.mp in_g with old | here
      · obtain ⟨kept, forgotten⟩ := told g old
        exact ⟨kept, fun not_waited => List.mem_append_left _ (forgotten not_waited)⟩
      · have : g = gf := by simpa using here
        subst this
        exact ⟨fun w => absurd w waited, fun _ => by simp⟩

/-- `prepared`, told `Prepared` by a pull that is preparing, with groups named once and unknown to
the core, leaves the groups as the claim of Spec.lean says (the groups of the event, the layers new
to the core, and what `prepared` pushed to `out`). -/
theorem prepared_holds_the_groups (c : Core) (pull : Std.U32) (layers : alloc.vec.Vec Std.U32)
    (groups : alloc.vec.Vec GroupFact) (out : alloc.vec.Vec Action) (distinct_c : distinct c)
    (preparing : phase c pull (Phase.Running Step.Preparing))
    (groups_nodup : (groups.val.map (·.id)).Nodup)
    (groups_new : ∀ g ∈ groups.val, ∀ x ∈ c.groups.val, x.id ≠ g.id) :
    Ok (prepared c pull layers groups out) (fun r => ∃ t, r.2.val = out.val ++ t ∧
      ∀ g ∈ groups.val,
        (waitedFor c layers g → ∃ x ∈ r.1.groups.val, x.id = g.id ∧
          ∀ l, l ∈ x.needed_by.val ↔ l ∈ g.needed_by.val ∧ fresh c layers l) ∧
        (¬ waitedFor c layers g →
          Action.Forget (Work.Group g.id) ∈ t ∧ ∀ x ∈ r.1.groups.val, x.id ≠ g.id)) := by
  unfold prepared
  -- the pull is found, and is preparing: the answer is in time
  obtain ⟨q, in_q, named, is_preparing⟩ := preparing
  obtain ⟨j, in_range, rfl⟩ := List.getElem_of_mem in_q
  refine Ok.bind (pull_at_unique c pull distinct_c j in_range named) ?_
  rintro o ⟨n, rfl, is_j⟩
  refine Ok.bind (filter_keeps_preparing c n (by omega) (by simpa [is_j] using is_preparing)) ?_
  rintro at1 rfl
  -- the layers that are new
  refine Ok.bind (clone_layers layers) ?_; intro copy is_copy
  refine Ok.bind (fresh_layers c copy) ?_; intro new_layers is_new_layers
  have is_fresh : ∀ l, l ∈ new_layers.val ↔ fresh c layers l := by
    intro l; simp [fresh, is_new_layers, is_copy]
  simp only [alloc.vec.IntoIteratorVec.into_iter]
  refine Ok.bind (Ok.ok.mpr rfl : Ok (ok groups) fun it => it = groups) ?_
  rintro iter rfl
  refine Ok.bind (prepared_loop2_holds _ _ _ _ _ is_fresh) ?_
  rintro ⟨v, out1⟩ ⟨new, t, v_is, out_is, _, from_told, told⟩
  simp only [uncurry_eq]
  -- the rest puts the layers and the pull back: the groups are those of `v`
  refine Ok.bind (Ok.any _) ?_; intro iter1 _
  refine Ok.bind (Ok.any _) ?_; intro v1 _
  refine Ok.bind (Ok.any _) ?_; intro p _
  simp only [uncurry_eq]
  refine Ok.bind (Ok.any _) ?_; intro p1 _
  simp only [uncurry_eq]
  refine Ok.ok.mpr ⟨t, out_is, fun g in_g => ⟨fun waited => ?_, fun not_waited => ⟨?_, ?_⟩⟩⟩
  · obtain ⟨x, in_x, same, named_x⟩ := (told g in_g).1 waited
    exact ⟨x, by rw [v_is]; exact List.mem_append_right _ in_x, same, named_x⟩
  · exact (told g in_g).2 not_waited
  · -- a group of the table is of the name of a group of the event that is waited for, or old
    intro x in_x same
    rcases List.mem_append.mp (v_is ▸ in_x) with old | pushed
    · exact groups_new g in_g x old same
    · obtain ⟨g', in_g', same', waited'⟩ := from_told x pushed
      have : g' = g := List.inj_on_of_nodup_map groups_nodup in_g' in_g (same'.symm.trans same)
      exact not_waited (this ▸ waited')

/-- A group of a list is matched, by name and by the layers it is for, by a group of any other list
with the same keys (`groupKey`). -/
theorem match_of_keys {l l' : List Group} (same : l'.map groupKey = l.map groupKey) {x : Group}
    (in_x : x ∈ l) : ∃ y ∈ l', y.id = x.id ∧ y.needed_by = x.needed_by := by
  have : groupKey x ∈ l'.map groupKey := by rw [same]; exact List.mem_map_of_mem in_x
  obtain ⟨y, in_y, same_key⟩ := List.mem_map.mp this
  exact ⟨y, in_y, by simpa [groupKey] using congrArg Prod.fst same_key,
    by simpa [groupKey] using congrArg Prod.snd same_key⟩

/-- **A group is held for the new layers that need it** (the statement of Spec.lean): `step` of
`Prepared` is `prepared` then `advance`; `prepared` leaves the groups as said
(`prepared_holds_the_groups`), and `advance` changes only the state of a group
(`advance_keeps_pulls`) and only adds to the actions. -/
theorem a_group_is_held_for_the_new_layers_that_need_it :
    AGroupIsHeldForTheNewLayersThatNeedIt := by
  intro c now p layers groups out c' out' distinct_c preparing
    ⟨_, groups_nodup, groups_new⟩ returns
  have held : Ok (step c now (Event.Prepared p layers groups) out) (fun r =>
      ∀ g ∈ groups.val,
        (waitedFor c layers g → ∃ x ∈ r.1.groups.val, x.id = g.id ∧
          ∀ l, l ∈ x.needed_by.val ↔ l ∈ g.needed_by.val ∧ fresh c layers l) ∧
        (¬ waitedFor c layers g →
          asked out r.2 (Action.Forget (Work.Group g.id)) ∧
            ∀ x ∈ r.1.groups.val, x.id ≠ g.id)) := by
    unfold velarx_lazy_core.step
    refine Ok.bind (prepared_holds_the_groups c p layers groups out distinct_c preparing
      groups_nodup groups_new) ?_
    rintro ⟨c1, out1⟩ ⟨t, out1_is, held⟩
    dsimp only at out1_is
    refine (advance_keeps_pulls c1 now out1).mono ?_
    rintro r ⟨⟨t', pushed, _⟩, _, _, keys, _⟩ g in_g
    -- `advance` keeps the names and the layers of the groups, and `out` grows
    obtain ⟨waited, not_waited⟩ := held g in_g
    refine ⟨fun w => ?_, fun w => ?_⟩
    · -- the group `prepared` held is in the table `advance` leaves
      obtain ⟨x, in_x, same, named⟩ := waited w
      obtain ⟨y, in_y, same_id, same_needed_by⟩ := match_of_keys keys in_x
      exact ⟨y, in_y, same_id.trans same, fun l => same_needed_by ▸ named l⟩
    · -- the group `advance` leaves was in the table of `prepared`; the action stays asked
      obtain ⟨asked_forget, absent⟩ := not_waited w
      refine ⟨?_, fun y in_y same => ?_⟩
      · unfold asked
        rw [pushed, out1_is, List.append_assoc, List.drop_left]
        exact List.mem_append_left _ asked_forget
      · obtain ⟨x, in_x, same_id, _⟩ := match_of_keys keys.symm in_y
        exact absent x in_x (same_id.trans same)
  exact held.eq returns

end LazyCore
