-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proof of `ALayerIsCommittedAfterItsGroups` (Spec.lean).  When the step
-- asks for `CommitLayer l`, the core it leaves has a layer `l` that is `Committing`, and every group
-- that names `l` is `Done`.
--
-- Why it is needed: committing a layer before the files of its groups are there is the bug "a layer
-- named in the store before its content is durable".  This is the claim that `advance` does not
-- make it, whatever the events before.
--
-- The argument follows the Rust, from the inside out:
--   1. Only `advance` asks for `CommitLayer`, in its first loop, over the layers.  Every other
--      function that `step` calls before `advance` pushes actions of other kinds (`f_kinds`,
--      Grows.lean, of each function).
--   2. The first loop of `advance` asks for the commit of a layer only after `waits_for_groups`
--      said no (`waits_for_groups_no`: no group that names the layer is not done), and puts the
--      layer back `Committing` (`advance_loop2_commits`).
--   3. The two later loops of `advance` do not undo it: the loop over the pulls does not touch the
--      layers or the groups, and the loop over the groups only turns a group that is `Todo` into
--      `Sent`, so a group that was `Done` stays `Done` (`advance_loop4_groups`).
--   4. `step_commits` puts the pieces together for every event (the walk of the events of `step` is
--      Step.lean), and the claim follows.
--
-- Read before this file: Grows.lean (`AppendsOnly`, `AppendsKinds`), Pulls.lean, Step.lean, and the
-- statement in Spec.lean.
--
-- Notation: `Ok m P` is "if `m` returns, its result satisfies `P`"; `AppendsOnly (OfKinds ks) old l`
-- is "`l` is `old` with actions of the kinds `ks` added at the end"; `l.set i x` is the list `l` with
-- `x` at `i`; `r.1`, `r.2` are the first and second element of a pair.
import LazyCore.Step

open Aeneas Aeneas.Std Result velarx_lazy_core

namespace LazyCore

/-- `LayerState::ne` says yes exactly when the state is not `Fetching`. -/
theorem layer_ne_fetching (s : LayerState) :
    Ok (core.cmp.PartialEq.ne.trait_default LayerState.Insts.CoreCmpPartialEqLayerState s
      LayerState.Fetching) (fun b => b = true ↔ s ≠ LayerState.Fetching) := by
  unfold core.cmp.PartialEq.ne.trait_default core.cmp.PartialEq.ne.default
  simp only [LayerState.Insts.CoreCmpPartialEqLayerState.eq]
  cases s <;> simp [LayerState.read_discriminant] <;> exact Ok.ok.mpr (by simp)

/-- `GroupState::ne` says yes exactly when the state is not `Done`. -/
theorem group_ne_done (s : GroupState) :
    Ok (core.cmp.PartialEq.ne.trait_default GroupState.Insts.CoreCmpPartialEqGroupState s
      GroupState.Done) (fun b => b = true ↔ s ≠ GroupState.Done) := by
  unfold core.cmp.PartialEq.ne.trait_default core.cmp.PartialEq.ne.default
  simp only [GroupState.Insts.CoreCmpPartialEqGroupState.eq]
  cases s <;> simp [GroupState.read_discriminant] <;> exact Ok.ok.mpr (by simp)

/-- `GroupState::eq` with `Todo` says yes exactly when the state is `Todo`. -/
theorem group_eq_todo (s : GroupState) :
    Ok (GroupState.Insts.CoreCmpPartialEqGroupState.eq s GroupState.Todo)
      (fun b => b = true ↔ s = GroupState.Todo) := by
  unfold GroupState.Insts.CoreCmpPartialEqGroupState.eq
  cases s <;> simp [GroupState.read_discriminant] <;> exact Ok.ok.mpr (by simp)

/-- `GroupsDone groups x`: every group of `groups` that names the layer `x` is `Done`. -/
def GroupsDone (groups : List Group) (x : Std.U32) : Prop :=
  ∀ g ∈ groups, x ∈ g.needed_by.val → g.state = GroupState.Done

/-- The Rust `waits_for_groups` (a loop over the groups, stopping at the first that names the layer
and is not done) says no only if every group that names the layer is done. -/
theorem waits_for_groups_no (groups : Slice Group) (layer : Std.U32) :
    Ok (waits_for_groups groups layer) (fun b => b = false → GroupsDone groups.val layer) := by
  unfold waits_for_groups
  simp only [core.slice.Slice.iter, bind_ok]
  unfold waits_for_groups_loop
  -- the groups before the iterator are all seen: the ones that name the layer are done
  refine Ok.loop (I := fun it : core.slice.iter.Iter Group =>
     it.slice = groups ∧ it.i ≤ groups.val.length ∧
       ∀ g ∈ groups.val.take it.i, layer ∈ g.needed_by.val → g.state = GroupState.Done) ?_
    ⟨rfl, by simp, by simp⟩
  rintro it ⟨same, in_range, seen⟩
  unfold waits_for_groups_loop.body core.slice.iter.IteratorSliceIter.next
  dsimp only
  by_cases more : it.i < it.slice.len
  · have more' : it.i < it.slice.val.length := by simpa using more
    simp only [more, ↓reduceDIte, bind_ok]
    generalize hg : it.slice[it.i] = g
    have current : it.slice.val[it.i] = g := hg
    have more'' : it.i < groups.val.length := by simpa [same] using more'
    -- the groups seen after this round: those before, and this one
    have seen_next : (layer ∈ g.needed_by.val → g.state = GroupState.Done) →
        ∀ y ∈ List.take (it.i + 1) groups.val, layer ∈ y.needed_by.val →
          y.state = GroupState.Done := by
      intro ok_g y hy named
      rw [List.take_succ_eq_append_getElem more''] at hy
      rcases List.mem_append.mp hy with before | here
      · exact seen y before named
      · have : y = g := by rw [List.mem_singleton.mp here, ← current]; simp [same]
        subst this; exact ok_g named
    -- the group names the layer (`contains`)
    have contains := anyM_pure (core.cmp.PartialEqU32.eq layer) (fun y => layer = y)
      (fun x => rfl) (alloc.vec.Vec.deref g.needed_by).val
    refine Ok.bind (Q := fun b => b = decide (layer ∈ g.needed_by.val)) ?_ ?_
    · unfold core.slice.Slice.contains
      rw [contains]; simp only [alloc.vec.Vec.deref] at *
      exact Ok.ok.mpr (by simp)
    intro b is_b
    subst is_b
    by_cases named : layer ∈ g.needed_by.val
    · simp only [decide_eq_true_eq, named, ↓reduceIte]
      refine Ok.bind (group_ne_done g.state) ?_
      intro b1 is_b1
      by_cases done : g.state = GroupState.Done
      · -- it is done: the loop goes on
        have : b1 = false := by simpa [done] using is_b1
        simp only [this]
        exact Ok.ok.mpr ⟨same, by show it.i + 1 ≤ groups.val.length; omega, seen_next fun _ => done⟩
      · -- it is not done: the answer is yes
        have : b1 = true := is_b1.mpr done
        simp only [this]
        exact Ok.ok.mpr (by simp)
    · simp only [decide_eq_true_eq, named, ↓reduceIte]
      exact Ok.ok.mpr ⟨same, by show it.i + 1 ≤ groups.val.length; omega,
        seen_next fun h => absurd h named⟩
  · -- no more groups: all of them were seen
    simp only [more, ↓reduceDIte, bind_ok]
    refine Ok.ok.mpr fun _ g hg named => ?_
    have : groups.val.length ≤ it.i := by simpa [same] using more
    exact seen g (by rwa [List.take_of_length_le this]) named

/-- The loop of `advance` over the layers (`for l in layers.iter_mut()`) asks for the commit of a
layer `x` (`CommitLayer x`) only when no group of `groups` that names `x` is not done, and leaves in
the table a layer named `x` that is `Committing`. -/
theorem advance_loop2_commits (l : List Layer) (iter : core.slice.iter.IterMut Layer)
    (cfg : Cfg) (out : alloc.vec.Vec Action) (working committing : Std.Usize)
    (groups : alloc.vec.Vec Group) (start : iter.slice.val = l ∧ iter.i = 0) :
    Ok (advance_loop2 iter (fun im => im) cfg out working committing groups) (fun r =>
      ∃ t, r.2.1.val = out.val ++ t ∧ ∀ x, Action.CommitLayer x ∈ t →
        GroupsDone groups.val x ∧
          ∃ b ∈ (r.2.2.2 r.2.2.1).slice.val, b.id = x ∧ b.state = LayerState.Committing) := by
  unfold advance_loop2
  -- `pre` is what the loop has put back so far, and `t` what it has asked: a commit asked is of a
  -- layer of `pre` that is `Committing`
  refine Ok.loop (I := fun x : core.slice.iter.IterMut Layer × _ × alloc.vec.Vec Action × Std.Usize =>
    x.1.slice.val = l ∧ ∃ pre, (∀ it' : core.slice.iter.IterMut Layer,
      it'.slice.val.length = l.length → (x.2.1 it').slice.val = pre ++ it'.slice.val.drop x.1.i) ∧
    ∃ t, x.2.2.1.val = out.val ++ t ∧ ∀ y, Action.CommitLayer y ∈ t →
        GroupsDone groups.val y ∧ ∃ b ∈ pre, b.id = y ∧ b.state = LayerState.Committing) ?_
    ⟨start.1, [], by simp [start.2], [], by simp, by simp⟩
  rintro ⟨it, back, out1, committing1⟩ ⟨same, pre, gives, t, grown, asked⟩
  dsimp only at same gives grown asked
  unfold advance_loop2.body core.slice.iter.IteratorIterMut.next
  dsimp only
  by_cases more : it.i < it.slice.len
  · have more' : it.i < it.slice.val.length := by simpa using more
    simp only [more, ↓reduceDIte, bind_ok]
    generalize hg : it.slice[it.i] = x
    -- the layer is put back (written) and the loop goes on: what was asked stays asked
    have written : ∀ y : Layer, ∀ it' : core.slice.iter.IterMut Layer,
        it'.slice.val.length = l.length →
        (back { it' with slice := it'.slice.setAtNat it.i y }).slice.val =
          (pre ++ [y]) ++ it'.slice.val.drop (it.i + 1) := by
      intro y it' same_length
      rw [gives _ (by simpa using same_length)]
      have in_l : it.i < it'.slice.val.length := by rw [same_length, ← same]; exact more'
      simp [Slice.setAtNat, List.drop_set_of_lt, List.drop_eq_getElem_cons, in_l]
    have carry : ∀ y : Layer, ∀ a, Action.CommitLayer a ∈ t →
        GroupsDone groups.val a ∧ ∃ c ∈ pre ++ [y], c.id = a ∧ c.state = LayerState.Committing :=
      fun y a asked_a => ⟨(asked a asked_a).1, let ⟨c, in_c, is_c⟩ := (asked a asked_a).2
        ⟨c, List.mem_append_left _ in_c, is_c⟩⟩
    -- `if l.state != Fetching { continue }`
    refine Ok.bind (layer_ne_fetching x.state) ?_; intro b is_b
    split
    · exact Ok.ok.mpr ⟨same, pre ++ [x], written x, t, grown, carry x⟩
    · -- `|| a group that names the layer is not done { continue }`
      refine Ok.bind (waits_for_groups_no _ _) ?_; intro b1 is_b1
      split
      · exact Ok.ok.mpr ⟨same, pre ++ [x], written x, t, grown, carry x⟩
      · have done : GroupsDone groups.val x.id := by
          simpa [alloc.vec.Vec.deref] using is_b1 (by simpa using ‹¬ b1 = true›)
        split
        · -- `if c.driver_pulls { l.state = Ready }`
          exact Ok.ok.mpr ⟨same, pre ++ [{ x with state := LayerState.Ready }],
            written _, t, grown, carry _⟩
        · split
          · -- `else if committing < working`: the layer is `Committing`, and the commit asked
            refine Ok.bind (Ok.any _) ?_; intro committing2 _
            refine Ok.bind (push_appends _ _) ?_; intro out2 pushed
            refine Ok.ok.mpr ⟨same, pre ++ [{ x with state := LayerState.Committing }],
              written _, t ++ [Action.CommitLayer x.id], by simp [pushed, grown], ?_⟩
            intro a in_a
            rcases List.mem_append.mp in_a with before | here
            · exact carry _ a before
            · have : a = x.id := by simpa using here
              subst this
              exact ⟨done, { x with state := LayerState.Committing }, by simp, rfl, rfl⟩
          · exact Ok.ok.mpr ⟨same, pre ++ [x], written x, t, grown, carry x⟩
  · -- the loop ends: the table is what was put back
    have at_end : l.length ≤ it.i := by simpa [same] using more
    simp only [more, ↓reduceDIte, bind_ok]
    refine Ok.ok.mpr ⟨t, grown, fun y asked_y => ?_⟩
    refine ⟨(asked y asked_y).1, ?_⟩
    obtain ⟨b, in_pre, is_b⟩ := (asked y asked_y).2
    refine ⟨b, ?_, is_b⟩
    simp only [gives it (by rw [same]), same, List.drop_eq_nil_of_le at_end, List.append_nil]
    exact in_pre

/-- The loop of `advance` over the groups of a pull (`for g in 0..groups.len()`) keeps a layer's
groups done: the only group it changes is one that is `Todo`, which becomes `Sent`, so if every group
that names `x` is done before, every group that names `x` is done after. -/
theorem advance_loop4_loop0_groups (iter : core.ops.range.Range Std.Usize)
    (pulls : alloc.vec.Vec Pull) (v : alloc.vec.Vec Group) (out : alloc.vec.Vec Action)
    (p : Std.Usize) (limit id sent : Std.U32) :
    Ok (advance_loop4_loop0 iter pulls v out p limit id sent)
      (fun r => ∀ x, GroupsDone v.val x → GroupsDone r.1.val x) := by
  unfold advance_loop4_loop0
  refine Ok.loop (I := fun x => ∀ y, GroupsDone v.val y → GroupsDone x.2.1.val y) ?_ fun _ h => h
  rintro ⟨iter, v1, out1, sent1⟩ kept
  dsimp only at kept
  unfold advance_loop4_loop0.body
  refine Ok.bind (Ok.any _) ?_; rintro ⟨o, iter1⟩ _
  cases o with
  | none => exact Ok.ok.mpr kept
  | some g =>
    dsimp only
    split
    · -- `if state == Todo && the pull wants it`: the group is sent
      refine Ok.bind (index_result _ _) ?_; rintro g1 ⟨in_range1, is_g1⟩
      refine Ok.bind (group_eq_todo g1.state) ?_; intro todo is_todo
      split
      · refine Ok.bind (Ok.any _) ?_; intro _ _
        refine Ok.bind (Ok.any _) ?_; intro _ _
        split
        · refine Ok.bind (index_mut_result _ _) ?_; rintro _ ⟨in_range, rfl⟩
          simp only [uncurry_eq]
          refine Ok.bind (Ok.any _) ?_; intro _ _
          refine Ok.bind (Ok.any _) ?_; intro _ _
          refine Ok.bind (Ok.any _) ?_; intro _ _
          refine Ok.ok.mpr fun y done => ?_
          intro g' in_g' named
          rw [set_val] at in_g'
          rcases List.mem_or_eq_of_mem_set in_g' with old | new
          · exact kept y done g' old named
          · -- the group that is sent names `y`: it was `Todo`, so not done, against `kept`
            subst new
            have is_done := kept y done _ (List.getElem_mem in_range) named
            have is_todo' := is_todo.mp ‹todo = true›
            rw [is_g1] at is_todo'
            rw [is_todo'] at is_done
            cases is_done
        · exact Ok.ok.mpr kept
      · exact Ok.ok.mpr kept
    · exact Ok.ok.mpr kept

/-- The loop of `advance` over the pulls that fetch (`for p in 0..pulls.len()`) keeps a layer's
groups done, by `advance_loop4_loop0_groups`. -/
theorem advance_loop4_groups (iter : core.ops.range.Range Std.Usize) (cfg : Cfg)
    (pulls : alloc.vec.Vec Pull) (layers : alloc.vec.Vec Layer) (groups : alloc.vec.Vec Group)
    (starts : alloc.vec.Vec ContainerStart) (now : Std.U64) (out : alloc.vec.Vec Action) :
    Ok (advance_loop4 iter cfg pulls layers groups starts now out)
      (fun r => ∀ x, GroupsDone groups.val x → GroupsDone r.2.1.val x) := by
  unfold advance_loop4
  refine Ok.loop (I := fun x => ∀ y, GroupsDone groups.val y → GroupsDone x.2.1.val y) ?_
    fun _ h => h
  rintro ⟨iter, v1, out1⟩ kept
  dsimp only at kept
  unfold advance_loop4.body
  repeat (first
    | exact Ok.ok.mpr kept
    | -- the inner loop sends the groups the pull wants
      (refine Ok.bind (advance_loop4_loop0_groups _ _ _ _ _ _ _ _) ?_
       rintro ⟨v2, out2⟩ done2
       exact Ok.ok.mpr fun y h => done2 y (kept y h))
    | (refine Ok.bind (Ok.any _) ?_; intro _ _)
    | simp only [uncurry_eq]
    | split)

/-- `CommitsOk c new`: of the actions `new` that a step added, a commit of a layer `x` is only there
if the core `c` the step leaves has a layer named `x` that is `Committing`, and every group of `c`
that names `x` is `Done`. -/
def CommitsOk (c : Core) (new : List Action) : Prop :=
  ∀ x, Action.CommitLayer x ∈ new →
    (∃ b ∈ c.layers.val, b.id = x ∧ b.state = LayerState.Committing) ∧ GroupsDone c.groups.val x

/-- The kinds of every action but `CommitLayer`. -/
abbrev notCommitKinds : List Kind :=
  [.record, .prepare, .driverPull, .commitImage, .fetch, .abortPull, .abortOther, .forget, .endPull,
   .wake]

/-- Actions that are of the kinds of `notCommitKinds` are no commit of a layer, so they are
`CommitsOk` trivially. -/
theorem CommitsOk.of_none {c : Core} {new : List Action}
    (none : ∀ a ∈ new, OfKinds notCommitKinds a) : CommitsOk c new :=
  fun x asked => by have := none _ asked; simp [OfKinds, kindOf] at this

/-- What a function pushes, when it pushes actions of the kinds `ks` that are among
`notCommitKinds`, is no commit of a layer. -/
theorem AppendsOnly.notCommit {ks : List Kind} {old l : List Action}
    (appends : AppendsOnly (OfKinds ks) old l) (sub : ks ⊆ notCommitKinds := by decide) :
    AppendsOnly (OfKinds notCommitKinds) old l :=
  appends.mono fun _ h => OfKinds.mono sub _ h

/-- `advance`, called after something that pushed no commit of a layer since `out`, leaves a core
that is `CommitsOk` for what was pushed since `out`: the first loop asks for the commit of a layer
after the test of its groups and leaves it `Committing` (`advance_loop2_commits`), the loop over the
pulls pushes no commit of a layer and leaves the layers as they are, the third loop keeps the groups
that name it done (`advance_loop4_groups`), and what was pushed before `advance` is no commit. -/
theorem advance_commits (c : Core) (now : Std.U64) (out1 : alloc.vec.Vec Action)
    (out : List Action) (before : AppendsOnly (OfKinds notCommitKinds) out out1.val) :
    Ok (advance c now out1) (fun r => CommitsOk r.1 (r.2.val.drop out.length)) := by
  unfold advance
  simp only [lift, bind_ok, alloc.vec.Vec.deref_mut, core.slice.Slice.iter_mut,
    core.slice.Slice.iter, uncurry_eq]
  -- the counts of working pulls and of commits in progress
  refine Ok.bind (Ok.any _) ?_; intro working _
  refine Ok.bind (Ok.any _) ?_; intro committing _
  -- the loop over the layers
  refine Ok.bind (advance_loop2_commits c.layers.val _ _ _ _ _ _ ⟨rfl, rfl⟩) ?_
  rintro ⟨cfg1, out1, im, back⟩ ⟨t0, pushed0, commits0⟩
  simp only [uncurry_eq]
  -- the loop over the pulls pushes no commit of a layer
  refine Ok.bind ((advance_loop3_kinds _ _ _ _).appends) ?_
  rintro ⟨out2, im1, back1⟩ kinds1
  simp only [uncurry_eq]
  -- the loop over the groups keeps them done, and pushes no commit of a layer
  refine Ok.bind (Ok.and (advance_loop4_groups _ _ _ _ _ _ _ _)
    ((advance_loop4_kinds _ _ _ _ _ _ _ _).appends)) ?_
  rintro ⟨c2, v, out3⟩ ⟨done2, kinds2⟩
  obtain ⟨tb, is_out1, in_tb⟩ := before.appended
  obtain ⟨t1, pushed1, in_t1⟩ := kinds1.appended
  obtain ⟨t2, pushed2, in_t2⟩ := kinds2.appended
  refine Ok.ok.mpr fun x asked_x => ?_
  have drop_is : out3.val.drop out.length = tb ++ t0 ++ t1 ++ t2 := by
    rw [pushed2, pushed1, pushed0, is_out1]; simp
  rw [drop_is] at asked_x
  simp only [List.mem_append] at asked_x
  rcases asked_x with ((in_tb' | in_t0) | in_t1') | in_t2'
  · have := in_tb _ in_tb'; simp [OfKinds, kindOf] at this
  · obtain ⟨done, b, in_b, is_b⟩ := commits0 x in_t0
    exact ⟨⟨b, in_b, is_b⟩, done2 x done⟩
  · have := in_t1 _ in_t1'; simp [OfKinds, kindOf] at this
  · have := in_t2 _ in_t2'; simp [OfKinds, kindOf] at this

/-- A `Wake` pushed after something that is `CommitsOk` is `CommitsOk`: a `Wake` is no commit. -/
theorem CommitsOk.wake {c : Core} {out out1 : alloc.vec.Vec Action} {old : List Action}
    (ok : CommitsOk c (out.val.drop old.length)) {t : Std.U64}
    (pushed : out1.val = out.val ++ [Action.Wake t]) : CommitsOk c (out1.val.drop old.length) := by
  intro x asked
  rw [pushed, List.drop_append] at asked
  rcases List.mem_append.mp asked with before | wake
  · exact ok x before
  · have := List.mem_of_mem_drop wake
    simp at this

/-- **Every event.**  Whatever the event, what the step asks for is `CommitsOk` in the core it leaves:
each event is a call of one function of lib.rs (then `advance`), or code of `step` itself
(`Step.lean`); the functions called before `advance` push no commit of a layer, `advance` leaves a
core that is `CommitsOk` for what it pushed (`advance_commits`), and the events that do not
call `advance` push none at all. -/
theorem step_commits (c : Core) (now : Std.U64) (ev : Event) (out : alloc.vec.Vec Action) :
    Ok (step c now ev out) (fun r => CommitsOk r.1 (r.2.val.drop out.val.length)) :=
  have nothing : AppendsOnly (OfKinds notCommitKinds) out.val out.val := AppendsOnly.refl _
  have none_asked : ∀ c' : Core, CommitsOk c' (out.val.drop out.val.length) :=
    fun _ => CommitsOk.of_none (by simp)
  StepFacts.holds (told := fun _ => True)
    (A := fun r => AppendsOnly (OfKinds notCommitKinds) out.val r.2.val)
    (Q := fun r => CommitsOk r.1 (r.2.val.drop out.val.length))
    { advance_ok := fun r before => advance_commits r.1 now r.2 out.val before
      add_ok := fun pull containers =>
        (add_kinds c pull containers out).appends.mono fun _ h => h.notCommit
      cancel_ok := fun pull => (cancel_kinds c pull out).appends.mono fun _ h => h.notCommit
      prepared_ok := fun pull layers groups _ =>
        (prepared_kinds c pull layers groups out).appends.mono fun _ h => h.notCommit
      succeeded_ok := fun work =>
        (succeeded_kinds c work out).appends.mono fun _ h => h.notCommit
      failed_ok := fun work cl =>
        (failed_kinds c now work cl out).appends.mono fun _ h => h.notCommit
      hurry_of_none := none_asked c
      hurry_boosts := fun _ _ => nothing
      hurry_begins := fun at_ in_range _ =>
        (begin_try_kinds _ at_ out).appends.mono fun _ h => h.notCommit
      start_of_a_layer := fun layer =>
        (Ok.any (start_at c layer now)).mono fun _ _ cs => none_asked _
      wake := fun _ ok _ _ pushed => ok.wake pushed
      tick_loop := fun iter =>
        (step_loop_kinds iter c now out).appends.mono fun _ h => h.notCommit } ev trivial

/-- **A layer is committed after its groups** (the statement of Spec.lean): the step asks for the
commit of a layer only if `advance` did (`step_commits`), and then the core it leaves has the layer
`Committing` and every group that names it `Done`. -/
theorem a_layer_is_committed_after_its_groups : ALayerIsCommittedAfterItsGroups := by
  intro c now ev out c' out' l returns asked_l
  exact ((step_commits c now ev out).eq returns) l asked_l

end LazyCore
