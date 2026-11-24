-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proof of `ACancelMakesTheSharersPlanAgain` (Spec.lean).
-- When a pull that runs is cancelled, every other pull that is working and lacks one
-- of its layers is made to prepare again: it is `Running Preparing` after the step, and
-- the step asked for `Prepare` of it.  What it held was planned for the cancelled pull.
--
-- The argument follows the Rust, `step` then `cancel` then `advance`:
--   1. `cancel` finds the pull `p` (`pull_at`; the names are distinct, so it is the pull
--      the statement speaks of), copies its layers (`mine`), marks it `Cancelling`, lets go
--      of its layers (`let_go`: only the pull `p` changes, so the sharer `q` is still
--      there, working, with its layers), and pushes `Abort (Pull p)`.
--   2. `lacking(&mine)` returns the names of the working pulls that lack one of `mine`:
--      `q` is one of them (`lacking_complete`, Verdict.lean).
--   3. The loop goes through those names; for each it calls `let_go` and `begin_try` for
--      the pull of that name, which is then `Running Preparing` and `Prepare` of it is
--      pushed.  The later rounds, which are for other pulls, leave it so.
--   4. `advance` leaves a pull that is not working as it is, and only pushes.
--
-- Read before this file: Ok.lean, Grows.lean, Pulls.lean, Verdict.lean, Names.lean, and
-- the statement in Spec.lean.
--
-- Notation: besides the notations of the files above (`Ok m P` is "if `m` returns, its
-- result satisfies `P`"; `l1 <+: l2` is "`l1` is the beginning of `l2`"), `phase c q ph` is
-- "the core holds a pull named `q` that is at `ph`" (Spec.lean), and `x ∈ l.set i y` is
-- "x is in the list `l` with `y` put at the place `i`".
import LazyCore.Names

open Aeneas Aeneas.Std Result velarx_lazy_core

namespace LazyCore

/-- Two pulls of a core with distinct names that have the same name are the same pull. -/
theorem same_pull_of_same_name {c : Core} (distinct_c : distinct c) {x y : Pull}
    (in_x : x ∈ c.pulls.val) (in_y : y ∈ c.pulls.val) (same_name : x.id = y.id) : x = y :=
  List.inj_on_of_nodup_map distinct_c in_x in_y same_name

/-- `Vec::clone` of a vector of `u32` is a vector with the same elements. -/
theorem clone_layers (v : alloc.vec.Vec Std.U32) :
    Ok (alloc.vec.CloneVec.clone core.clone.CloneU32 v) (fun w => w.val = v.val) := by
  unfold alloc.vec.CloneVec.clone Slice.clone
  have same_list : ∀ l : List Std.U32,
      List.clone core.clone.CloneU32.clone l = ok ⟨l, rfl⟩ := by
    intro l
    induction l with
    | nil => rfl
    | cons a rest ih =>
      simp only [List.clone, List.mapM_with_length] at ih ⊢
      rw [ih]
      simp [liftFun1, core.clone.impls.CloneU32.clone, Functor.map]
  rw [same_list]
  simp
  exact Ok.ok.mpr rfl

/-- `Replanned q c out iter c1 out1`: the loop of `cancel`, begun with the core `c` and the
actions `out`, has left the core `c1` and the actions `out1`, with the names `iter` still to go
through.  The pulls have the names they had, `out1` is `out` followed by some actions `t`, and if
`q` is not among the names left (it was gone through), then `Prepare q` is in `t` and the pull
`q` is `Running Preparing`. -/
def Replanned (q : Std.U32) (c : Core) (out : alloc.vec.Vec Action)
    (iter : alloc.vec.into_iter.IntoIter Std.U32) (c1 : Core)
    (out1 : alloc.vec.Vec Action) : Prop :=
  c1.pulls.val.map (·.id) = c.pulls.val.map (·.id) ∧
  (∃ t, out1.val = out.val ++ t ∧ (q ∉ iter.val → Action.Prepare q ∈ t)) ∧
  (q ∉ iter.val → phase c1 q (Phase.Running Step.Preparing))

/-- The loop of `cancel` (`for other in c.lacking(&mine)`: `let_go` and `begin_try` of the pull of
each name) makes the pull `q` prepare again when `q` is among the names and the core holds it:
it is `Running Preparing` after the loop, and `Prepare q` was pushed. -/
theorem cancel_loop_replans (q : Std.U32) (iter : alloc.vec.into_iter.IntoIter Std.U32)
    (c : Core) (out : alloc.vec.Vec Action) (held_q : held c q) (listed : q ∈ iter.val) :
    Ok (cancel_loop iter c out) (fun r => phase r.1 q (Phase.Running Step.Preparing) ∧
      ∃ t, (out.val ++ t) <+: r.2.val ∧ Action.Prepare q ∈ t) := by
  unfold cancel_loop
  refine Ok.loop (I := fun x => Replanned q c out x.1 x.2.1 x.2.2) ?_
    ⟨rfl, ⟨[], by simp, fun not_listed => absurd listed not_listed⟩,
      fun not_listed => absurd listed not_listed⟩
  rintro ⟨it, c1, out1⟩ ⟨same_names, ⟨t, pushed, prepared_q⟩, preparing_q⟩
  dsimp only at same_names pushed prepared_q preparing_q
  unfold cancel_loop.body
  have held_q1 : held c1 q := held_iff_name.mpr (same_names ▸ held_iff_name.mp held_q)
  refine Ok.bind (into_iter_next _) ?_
  rintro ⟨o, it1⟩ (⟨rfl, is_empty⟩ | ⟨other, rest, rfl, cons, is_rest⟩)
  · -- no name is left: `q` was gone through
    refine Ok.ok.mpr ⟨preparing_q (by simp [is_empty]), t, ?_, prepared_q (by simp [is_empty])⟩
    simp [pushed]
  · -- the next name is `other`, the names left are `rest`
    have rest_is : it1.val = rest := is_rest
    refine Ok.bind (pull_at_result c1 other) ?_
    intro o1 found
    -- `q` is not among the names left if it is not `other` and was not among the names before
    have not_before : ∀ (_ : other ≠ q), q ∉ rest → q ∉ it.val :=
        fun other_not_q not_rest in_it => by
      rw [cons] at in_it
      rcases List.mem_cons.mp in_it with same | in_rest
      · exact other_not_q same.symm
      · exact not_rest in_rest
    cases o1 with
    | none =>
      -- no pull has that name: nothing is done (it is not `q`, which the core holds)
      have other_not_q : other ≠ q := by
        obtain ⟨x, in_x, named_q⟩ := held_q1
        exact fun same => found x in_x (named_q.trans same.symm)
      refine Ok.ok.mpr ⟨same_names, ⟨t, pushed, fun not_rest => ?_⟩, fun not_rest => ?_⟩
      · exact prepared_q (not_before other_not_q (by simpa [rest_is] using not_rest))
      · exact preparing_q (not_before other_not_q (by simpa [rest_is] using not_rest))
    | some at_ =>
      obtain ⟨in_range, named_other, _⟩ := found
      simp only []
      -- it lets go of its layers
      refine Ok.bind (let_go_changes_layers c1 at_ out1) ?_
      rintro ⟨c2, out2⟩ ⟨⟨⟨t2, pushed2⟩, _⟩, _, in_range2, ls, pulls2⟩
      dsimp only at pushed2 pulls2
      -- then its try begins again
      refine Ok.bind (begin_try_prepares c2 at_ out2) ?_
      rintro ⟨c3, out3⟩ ⟨_, _, _, in_range3, ⟨t3, pushed3, prepares_other⟩, pulls3⟩
      dsimp only at pushed3 pulls3
      have same_id2 : (c2.pulls.val[at_.val]).id = other := by
        simp [pulls2, alloc.vec.Vec.set, named_other]
      have c2_pulls : c2.pulls.val = c1.pulls.val.set at_.val
          { c1.pulls.val[at_.val] with layers := ls } := by simp [pulls2, alloc.vec.Vec.set]
      have c2_names : c2.pulls.val.map (·.id) = c1.pulls.val.map (·.id) := by
        rw [c2_pulls]; refine map_set_of_same (·.id) _ _ _ in_range ?_; rfl
      refine Ok.ok.mpr (show Replanned q c out it1 c3 out3 from ⟨?_, ⟨t ++ t2 ++ t3, ?_, ?_⟩, ?_⟩)
      · -- the names are the same
        rw [pulls3]
        exact (map_set_of_same (·.id) c2.pulls.val at_.val { c2.pulls.val[at_.val] with
          phase := Phase.Running Step.Preparing, progressed := false } in_range3 rfl).trans
          (c2_names.trans same_names)
      · -- what was pushed: the old, then what `begin_try` pushes
        rw [pushed3, ← pushed2, pushed]; simp
      · intro not_rest
        by_cases same : other = q
        · rw [same_id2, same] at prepares_other
          simp [prepares_other]
        · have := prepared_q (not_before same (by simpa [rest_is] using not_rest))
          simp [this]
      · intro not_rest
        by_cases same : other = q
        · -- the pull of `q` is the one that began its try
          have in_range_c3 : at_.val < c3.pulls.val.length := by
            rw [pulls3]; simpa using in_range3
          refine ⟨c3.pulls.val[at_.val], List.getElem_mem in_range_c3, ?_, ?_⟩
          · simp [pulls3, same_id2, same]
          · simp [pulls3]
        · -- another pull: it is as it was
          obtain ⟨x, in_x, named_q, preparing⟩ :=
            preparing_q (not_before same (by simpa [rest_is] using not_rest))
          refine ⟨x, ?_, named_q, preparing⟩
          have in_c2 : x ∈ c2.pulls.val := by
            rw [c2_pulls]
            exact mem_set_of_other (·.id) _ in_range in_x
              fun e => same (named_other.symm.trans (e.symm.trans named_q))
          rw [pulls3]
          exact mem_set_of_other (·.id) _ in_range3 in_c2
            fun e => same (same_id2.symm.trans (e.symm.trans named_q))

/-- `cancel` of a pull that runs makes a working pull `q` that shares a layer with it prepare
again: `q` is `Running Preparing` after it, and `Prepare q` was pushed. -/
theorem cancel_replans (c : Core) (p q : Std.U32) (s : Step) (out : alloc.vec.Vec Action)
    (distinct_c : distinct c) (running : phase c p (Phase.Running s)) (not_p : q ≠ p)
    (working_q : phase c q (Phase.Running Step.Working)) (shared : share c p q) :
    Ok (cancel c p out) (fun r => phase r.1 q (Phase.Running Step.Preparing) ∧
      ∃ t, (out.val ++ t) <+: r.2.val ∧ Action.Prepare q ∈ t) := by
  obtain ⟨x, in_x, named_p, y, in_y, named_q, layer, in_x_layers, in_y_layers⟩ := shared
  obtain ⟨y2, in_y2, named_q2, working_y2⟩ := working_q
  obtain ⟨x2, in_x2, named_p2, running_x2⟩ := running
  -- the pull `p` is at the place `n`, and it is the pull `x`; the pull `q` is `y`
  obtain ⟨n, in_range, rfl⟩ : ∃ n : Nat, ∃ h : n < c.pulls.val.length, c.pulls.val[n] = x2 :=
    let ⟨n, h, is_x2⟩ := List.getElem_of_mem in_x2; ⟨n, h, is_x2⟩
  have x_is : x = c.pulls.val[n] := same_pull_of_same_name distinct_c in_x
    (List.getElem_mem in_range) (named_p.trans named_p2.symm)
  have y_is : y = y2 :=
    same_pull_of_same_name distinct_c in_y in_y2 (named_q.trans named_q2.symm)
  subst x_is y_is
  unfold cancel
  -- the pull is found at `n`
  refine Ok.bind (pull_at_unique c p distinct_c n in_range named_p2) ?_
  rintro o ⟨found, rfl, found_is⟩
  simp only []
  subst found_is
  -- the phase of the pull is read: it runs
  rw [index_in_range _ _ in_range]
  simp only [bind_ok]
  rw [running_x2]
  simp only []
  -- `mine` is a copy of its layers
  refine Ok.bind (clone_layers _) ?_; intro mine mine_is
  -- it is marked `Cancelling` and lets go of its layers: only its layers change
  rw [index_mut_in_range _ _ in_range]
  simp only [bind_ok, uncurry_eq]
  refine Ok.bind (let_go_changes_layers _ _ _) ?_
  rintro ⟨c1, out1⟩ ⟨⟨⟨t, pushed_by_let_go⟩, _⟩, _, in_range1, ls, pulls1⟩
  dsimp only at pushed_by_let_go pulls1
  simp only [uncurry_eq]
  refine Ok.bind (push_appends _ _) ?_; intro out2 pushed_abort
  -- the pull `q` is still there, working, with its layers: only the pull of `p` changed
  have y_in_c1 : y ∈ c1.pulls.val := by
    rw [pulls1]
    simp only [alloc.vec.Vec.set, alloc.vec.Vec.from_val]
    have other : y.id ≠ (c.pulls.val[found.val]).id := by rwa [named_p2, named_q]
    exact mem_set_of_other (·.id) _ (by simpa using in_range)
      (mem_set_of_other (·.id) _ in_range in_y other) (by simpa using other)
  -- the pulls that lack a layer of `p`: `q` is one of them
  refine Ok.bind (lacking_complete c1 _) ?_; intro names listed
  refine Ok.bind (P := _) (Q := fun iter => iter = names)
    (show Ok (ok names) _ from Ok.ok.mpr rfl) ?_
  intro iter is_names
  rw [is_names]
  have q_listed : q ∈ names.val := by
    have := listed y y_in_c1 working_y2 ⟨layer, by simp [alloc.vec.Vec.deref, mine_is, in_x_layers],
      in_y_layers⟩
    rwa [named_q] at this
  -- each of them is made to prepare again
  refine (cancel_loop_replans q names c1 out2 ⟨y, y_in_c1, named_q⟩ q_listed).mono ?_
  rintro r ⟨preparing, t2, pushed2, prepares⟩
  refine ⟨preparing, t ++ [Action.Abort (Work.Pull p)] ++ t2, ?_, by simp [prepares]⟩
  simpa [pushed_abort, ← pushed_by_let_go] using pushed2

/-- **A cancel makes the sharers plan again** (the statement of Spec.lean).  `step` on `Cancel p`
is `cancel` followed by `advance`: `cancel` makes `q` prepare again, and `advance` leaves a pull
that is not working as it is and only pushes. -/
theorem a_cancel_makes_the_sharers_plan_again : ACancelMakesTheSharersPlanAgain := by
  intro c now p q s out c' out' distinct_c running not_p working_q shared returns
  have replans : Ok (step c now (Event.Cancel p) out) (fun r =>
      phase r.1 q (Phase.Running Step.Preparing) ∧ asked out r.2 (Action.Prepare q)) := by
    unfold step
    -- `cancel`
    refine Ok.bind (cancel_replans c p q s out distinct_c running not_p working_q shared) ?_
    rintro ⟨c1, out1⟩ ⟨preparing, t, pushed, prepares⟩
    simp only [uncurry_eq]
    -- `advance`: the pull is not working, so it stays as it is
    refine (advance_keeps_pulls c1 now out1).mono ?_
    rintro r ⟨⟨t2, pushed2, _⟩, kept, _⟩
    refine ⟨?_, asked_if_appended (l := t) ?_ prepares⟩
    · obtain ⟨x, in_x, named_q, is_preparing⟩ := preparing
      obtain ⟨j, in_range, rfl⟩ := List.getElem_of_mem in_x
      obtain ⟨in_range', kept_x⟩ := kept_at kept j in_range
      refine ⟨_, List.getElem_mem in_range', kept_x.1.trans named_q, ?_⟩
      rw [kept_x.2.1 (by rw [is_preparing]; simp), is_preparing]
    · rw [pushed2]; exact pushed.trans (List.prefix_append _ _)
  exact replans.eq returns
end LazyCore
