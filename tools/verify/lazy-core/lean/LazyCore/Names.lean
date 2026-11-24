-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proof of `TheNamesStayDistinct` and of
-- `ANewCoreHasNoPull` (Spec.lean).  No two pulls of a core have the same
-- name, and `step` keeps it so.
--
-- Why it is needed: every other claim of Spec.lean assumes `distinct c`.
-- This file is what lets that hypothesis be discharged by induction on the
-- steps, from `Core::new`.  It says nothing of a pull being stopped.
--
-- The argument follows the Rust, from the inside out, one fact per
-- function of lib.rs that touches the pulls, each of the shape
--
--     distinct c   gives   Ok (f c ...) (fun r => distinct r.1)
--
-- read "if the names of the pulls of `c` are distinct and `f` returns, the
-- names of the pulls it leaves are distinct".  Most functions leave the
-- list of the names as it is (`begin_try`, `let_go`, `advance`, `prepared`,
-- `progress`, ...); `leave` erases one name; `add` appends a name that
-- `pull_at` did not find.  The facts compose along the calls, in the order
-- of lib.rs from the bottom up: `begin_try`, `let_go`, `leave` (with its
-- loop), `try_failed`, `advance`, `add`, `cancel` (with its loop),
-- `succeeded`, `failed` (with its loop), `prepared`, the loop of a `Tick`,
-- and last `step`, whose walk of the events is Step.lean (each file gives the facts of its claim).
--
-- Read before this file: Ok.lean, Grows.lean, Pulls.lean, Verdict.lean, Step.lean, and
-- the two statements in Spec.lean.
--
-- Notation: besides the notations of the files above, `distinct c` is
-- "the list of the names of the pulls of `c` has no element twice"
-- (Spec.lean), and `Ok m P` is "if `m` returns, its result satisfies `P`".
import LazyCore.Verdict
import LazyCore.Step

open Aeneas Aeneas.Std Result velarx_lazy_core

namespace LazyCore

attribute [local irreducible] begin_try let_go_loop0 let_go_loop1 let_go leave_loop leave
  cancel_loop cancel advance_loop2 advance_loop3 advance_loop4_loop0 advance_loop4 advance
  Core.pull_at Core.lacking slots_held goes wanting in_flight Core.starting Pull.has_all
  Pull.working Pull.wants Pull.lacks

/-- A core whose pulls have the names of a core with distinct names has distinct names. -/
theorem distinct_of_same_names {c c' : Core} (distinct_c : distinct c)
    (same_names : c'.pulls.val.map (·.id) = c.pulls.val.map (·.id)) : distinct c' := by
  unfold distinct
  rw [same_names]
  exact distinct_c

/-- Putting a pull of the same name at the place `i` keeps the names distinct. -/
theorem distinct_of_set {c c' : Core} (distinct_c : distinct c) (i : Nat) (q : Pull)
    (in_range : i < c.pulls.val.length) (same_id : q.id = (c.pulls.val[i]).id)
    (pulls' : c'.pulls.val = c.pulls.val.set i q) : distinct c' :=
  distinct_of_same_names distinct_c
    (by rw [pulls']; exact map_set_of_same (·.id) _ _ _ in_range same_id)

/-- Adding at the end a pull whose name no pull has keeps the names distinct. -/
theorem distinct_of_push {c : Core} (distinct_c : distinct c) (v : alloc.vec.Vec Pull)
    (q : Pull) (v_is : v.val = c.pulls.val ++ [q]) (new : q.id ∉ c.pulls.val.map (·.id)) :
    distinct { c with pulls := v } := by
  unfold distinct
  dsimp only
  rw [v_is, List.map_append, List.nodup_append]
  refine ⟨distinct_c, by simp, ?_⟩
  intro a in_c b is_new same
  simp only [List.map_cons, List.map_nil, List.mem_singleton] at is_new
  exact new (is_new ▸ same ▸ in_c)

/-- `begin_try` keeps the names distinct (it keeps the names). -/
theorem begin_try_distinct (c : Core) (at_ : Std.Usize) (out : alloc.vec.Vec Action)
    (distinct_c : distinct c) : Ok (begin_try c at_ out) (fun r => distinct r.1) :=
  (begin_try_keeps_names c at_ out).mono
    fun _ ⟨_, _, names⟩ => distinct_of_same_names distinct_c names

/-- `let_go` keeps the names distinct: it changes only the layers of one pull. -/
theorem let_go_distinct (c : Core) (at_ : Std.Usize) (out : alloc.vec.Vec Action)
    (distinct_c : distinct c) : Ok (let_go c at_ out) (fun r => distinct r.1) := by
  refine (let_go_changes_layers c at_ out).mono ?_
  rintro r ⟨_, _, in_range, ls, pulls⟩
  exact distinct_of_set distinct_c at_.val { c.pulls.val[at_.val] with layers := ls } in_range rfl
    (by simp [pulls, alloc.vec.Vec.set])

/-- `leave` keeps the names distinct: it erases the name of one pull. -/
theorem leave_distinct (c : Core) (at_ : Std.Usize) (out : alloc.vec.Vec Action)
    (distinct_c : distinct c) : Ok (leave c at_ out) (fun r => distinct r.1) := by
  refine (leave_removes_the_pull c at_ out).mono ?_
  rintro r ⟨_, _, _, names⟩
  unfold distinct
  rw [names]
  exact List.Nodup.sublist ((List.eraseIdx_sublist _ _).map _) distinct_c

/-- `try_failed` keeps the names distinct: it changes the pull at `at_` (not its name), then
`leave`s it or lets go of its layers. -/
theorem try_failed_distinct (c : Core) (now : Std.U64) (at_ : Std.Usize) (cl : Class)
    (out : alloc.vec.Vec Action) (distinct_c : distinct c) :
    Ok (try_failed c now at_ cl out) (fun r => distinct r.1) := by
  unfold try_failed
  refine Ok.bind (index_mut_result _ _) ?_
  rintro _ ⟨in_range, rfl⟩
  simp only [uncurry_eq]
  refine Ok.bind (Ok.any _) ?_; intro failures _
  refine Ok.bind (Ok.any _) ?_; rintro ⟨cfg, failures1, state⟩ _
  refine Ok.bind (push_appends _ _) ?_; intro out1 pushed_record
  -- the pull is put back, with another phase or failures but the same name
  have put_back : ∀ q : Pull, q.id = (c.pulls.val[at_.val]).id →
      distinct { c with cfg := cfg, pulls := alloc.vec.Vec.set c.pulls at_ q } := fun q same_id =>
    distinct_of_set distinct_c at_.val q in_range same_id (by simp [alloc.vec.Vec.set])
  -- the try is over (`_ => leave`)
  have over : ∀ q : Pull, q = { c.pulls.val[at_.val] with failures := failures1 } →
      Ok (leave { c with cfg := cfg, pulls := alloc.vec.Vec.set c.pulls at_ q } at_ out1)
        (fun r => distinct r.1) := by
    intro q is_q
    exact leave_distinct _ _ _ (put_back q (by rw [is_q]))
  -- the try waits (`Backoff | NoSpace`): `let_go`, then `Wake`
  have waits : ∀ (wake : Std.U64) (q : Pull),
      q = { c.pulls.val[at_.val] with phase := Phase.Waiting wake, failures := failures1 } →
      Ok (do
        let (c2, out2) ← let_go
          { c with cfg := cfg, pulls := alloc.vec.Vec.set c.pulls at_ q } at_ out1
        let out3 ← alloc.vec.Vec.push out2 (Action.Wake wake)
        ok (c2, out3)) (fun r => distinct r.1) := by
    intro wake q is_q
    refine Ok.bind (let_go_distinct _ _ _ (put_back q (by rw [is_q]))) ?_
    rintro ⟨c2, out2⟩ distinct2
    refine Ok.bind (push_appends _ _) ?_; intro out3 _
    exact Ok.ok.mpr distinct2
  rcases state with _ | _ | wait | wait | _ | _
  · exact over _ rfl   -- `Queued`
  · exact over _ rfl   -- `Running`
  · exact waits wait _ rfl   -- `Backoff(until)`
  · exact waits wait _ rfl   -- `NoSpace(until)`
  · exact over _ rfl   -- `NeedsCredentials`
  · exact over _ rfl   -- `Failed`

/-- `advance` keeps the names distinct: it keeps every pull, each `Kept`. -/
theorem advance_distinct (c : Core) (now : Std.U64) (out : alloc.vec.Vec Action)
    (distinct_c : distinct c) : Ok (advance c now out) (fun r => distinct r.1) :=
  (advance_keeps_pulls c now out).mono
    fun _ ⟨_, kept, _⟩ => distinct_of_same_names distinct_c (kept_names kept)

/-- `add` keeps the names distinct: a pull is added only when `pull_at` did not find its name. -/
theorem add_distinct (c : Core) (pull : Std.U32) (containers : Bool) (out : alloc.vec.Vec Action)
    (distinct_c : distinct c) : Ok (add c pull containers out) (fun r => distinct r.1) := by
  unfold add
  refine Ok.bind (pull_at_none c pull) ?_; intro o none_not_held
  cases o with
  | some n => exact Ok.ok.mpr distinct_c
  | none =>
  have not_in_names : pull ∉ c.pulls.val.map (·.id) :=
    fun in_names => none_not_held rfl (held_iff_name.mpr in_names)
  -- the new pull is last, and nobody had its name
  have added : ∀ (v : alloc.vec.Vec Pull) (q : Pull), q.id = pull →
      v.val = c.pulls.val ++ [q] → distinct { c with pulls := v } :=
    fun v q named v_is => distinct_of_push distinct_c v q v_is (named ▸ not_in_names)
  -- the try begins (`begin_try` of the last pull), or the pull is recorded as queued
  have began : ∀ (v : alloc.vec.Vec Pull) (q : Pull), q.id = pull → v.val = c.pulls.val ++ [q] →
      Ok (do let i2 ← (alloc.vec.Vec.len v - 1#usize)
             begin_try { c with pulls := v } i2 out) (fun r => distinct r.1) := by
    intro v q named v_is
    refine Ok.bind (pred_len _) ?_; intro i2 _
    exact begin_try_distinct _ _ _ (added v q named v_is)
  have recorded : ∀ (v : alloc.vec.Vec Pull) (q : Pull), q.id = pull → v.val = c.pulls.val ++ [q] →
      Ok (do let out1 ← alloc.vec.Vec.push out (Action.Record pull State.Queued)
             ok ({ c with pulls := v }, out1)) (fun r => distinct r.1) := by
    intro v q named v_is
    refine Ok.bind (push_appends _ _) ?_; intro out1 _
    exact Ok.ok.mpr (added v q named v_is)
  simp only [core.option.Option.is_some, Option.isSome_none, Bool.false_eq_true, ↓reduceIte]
  -- a free place: the pull is pushed and its try begins
  refine Ok.bind (Ok.any _) ?_; intro i _
  by_cases free : i < c.cfg.completers
  · simp only [free, ↓reduceIte]
    refine Ok.bind (push_appends _ _) ?_; intro v pushed
    exact began v _ rfl pushed
  · -- no place: the try begins only for a container, else the pull is recorded as queued
    simp only [free, ↓reduceIte]
    refine Ok.bind (push_appends _ _) ?_; intro v pushed
    cases containers
    · simp only [Bool.false_eq_true, ↓reduceIte]
      exact recorded v _ rfl pushed
    · simp only [↓reduceIte]
      exact began v _ rfl pushed

/-- The loop of `cancel` over the other pulls that lack a layer keeps the names distinct. -/
theorem cancel_loop_distinct (iter : alloc.vec.into_iter.IntoIter Std.U32) (c : Core)
    (out : alloc.vec.Vec Action) (distinct_c : distinct c) :
    Ok (cancel_loop iter c out) (fun r => distinct r.1) := by
  unfold cancel_loop
  refine Ok.loop (I := fun x => distinct x.2.1) ?_ distinct_c
  rintro ⟨it, c1, out1⟩ so_far
  dsimp only at so_far
  unfold cancel_loop.body
  refine Ok.bind (into_iter_next _) ?_
  rintro ⟨o, it1⟩ (⟨rfl, _⟩ | ⟨other, rest, rfl, cons, is_rest⟩)
  · exact Ok.ok.mpr so_far
  · refine Ok.bind (pull_at_sound c1 other) ?_
    intro o1 found
    cases o1 with
    | none => exact Ok.ok.mpr so_far
    | some at_ =>
      simp only []
      -- it lets go of its layers, then begins its try again
      refine Ok.bind (let_go_distinct c1 at_ out1 so_far) ?_
      rintro ⟨c2, out2⟩ distinct2
      refine Ok.bind (begin_try_distinct c2 at_ out2 distinct2) ?_
      rintro ⟨c3, out3⟩ distinct3
      exact Ok.ok.mpr distinct3

/-- `cancel` keeps the names distinct. -/
theorem cancel_distinct (c : Core) (pull : Std.U32) (out : alloc.vec.Vec Action)
    (distinct_c : distinct c) : Ok (cancel c pull out) (fun r => distinct r.1) := by
  unfold cancel
  refine Ok.bind (pull_at_sound c pull) ?_
  intro o found
  cases o with
  | none => exact Ok.ok.mpr distinct_c
  | some at_ =>
  obtain ⟨in_range, named⟩ := found at_ rfl
  simp only []
  rw [index_in_range _ _ in_range]
  simp only [bind_ok]
  split
  · exact leave_distinct c at_ out distinct_c
  · -- it runs: its phase becomes `Cancelling`, it lets go of its layers
    refine Ok.bind (Ok.any _) ?_; intro mine _
    rw [index_mut_in_range _ _ in_range]
    simp only [bind_ok, uncurry_eq]
    have marked : ∀ q : Pull, q = { c.pulls.val[at_.val] with phase := Phase.Cancelling } →
        distinct { c with pulls := alloc.vec.Vec.set c.pulls at_ q } := fun q is_q =>
      distinct_of_set distinct_c at_.val q in_range (by rw [is_q]) (by simp [alloc.vec.Vec.set])
    refine Ok.bind (let_go_distinct _ _ _ (marked _ rfl)) ?_
    rintro ⟨c1, out1⟩ distinct1
    simp only [uncurry_eq]
    refine Ok.bind (push_appends _ _) ?_; intro out2 _
    -- the other pulls that lacked a layer of it let go and begin their try again
    refine Ok.bind (Ok.any _) ?_; intro v1 _
    refine Ok.bind (Ok.any _) ?_; intro it _
    exact cancel_loop_distinct it c1 out2 distinct1
  · exact leave_distinct c at_ out distinct_c
  · exact Ok.ok.mpr distinct_c

/-- `succeeded` keeps the names distinct: it changes the pull it is told of (not its name) or
ends it (`leave`), and `progress` keeps every pull. -/
theorem succeeded_distinct (c : Core) (work : Work) (out : alloc.vec.Vec Action)
    (distinct_c : distinct c) : Ok (succeeded c work out) (fun r => distinct r.1) := by
  unfold succeeded
  cases work with
  | Pull pull =>
    refine Ok.bind (pull_at_sound c pull) ?_
    intro o found
    cases o with
    | none => exact Ok.ok.mpr distinct_c
    | some at_ =>
      obtain ⟨in_range, named⟩ := found at_ rfl
      simp only []
      rw [index_in_range _ _ in_range]
      simp only [bind_ok]
      split
      · exact Ok.ok.mpr distinct_c
      · split
        · exact Ok.ok.mpr distinct_c
        · exact Ok.ok.mpr distinct_c
        · -- the driver's pull ended: the pull works again
          refine Ok.bind (index_mut_result _ _) ?_
          rintro _ ⟨in_range', rfl⟩
          simp only [uncurry_eq]
          refine Ok.bind (Ok.any _) ?_; rintro ⟨s1, back1⟩ _
          simp only [uncurry_eq]
          refine Ok.bind (Ok.any _) ?_; rintro ⟨iter, back2⟩ _
          simp only [uncurry_eq]
          refine Ok.bind (Ok.any _) ?_; intro back _
          exact Ok.ok.mpr (distinct_of_set distinct_c at_.val
            { c.pulls.val[at_.val] with phase := Phase.Running Step.Working, progressed := true }
            in_range rfl (by simp [alloc.vec.Vec.set]))
        · exact leave_distinct c at_ out distinct_c
      · exact Ok.ok.mpr distinct_c
      · exact leave_distinct c at_ out distinct_c
  | Layer layer =>
    refine Ok.bind (Ok.any _) ?_; intro o _
    cases o with
    | none => exact Ok.ok.mpr distinct_c
    | some l =>
      simp only []
      refine Ok.bind (Ok.any _) ?_; intro l1 _
      refine Ok.bind (Ok.any _) ?_; intro committing _
      split
      · -- the commit of the layer ended: the pulls that lack it progress
        refine Ok.bind (Ok.any _) ?_; rintro ⟨l2, back⟩ _
        simp only [uncurry_eq]
        refine Ok.bind (Ok.any _) ?_; intro one _
        refine Ok.bind (progress_keeps_pulls _ _) ?_; rintro c1 ⟨kept, -⟩
        exact Ok.ok.mpr (distinct_of_same_names distinct_c (kept_names kept))
      · exact Ok.ok.mpr distinct_c
  | Group group =>
    refine Ok.bind (Ok.any _) ?_; intro o _
    cases o with
    | none => exact Ok.ok.mpr distinct_c
    | some g =>
      simp only []
      refine Ok.bind (Ok.any _) ?_; intro g1 _
      split
      · exact Ok.ok.mpr distinct_c
      · -- the fetch of the group ended: the pulls that lack its layers progress
        refine Ok.bind (Ok.any _) ?_; rintro ⟨g2, back⟩ _
        simp only [uncurry_eq]
        refine Ok.bind (Ok.any _) ?_; intro g3 _
        refine Ok.bind (Ok.any _) ?_; intro needed_by _
        refine Ok.bind (progress_keeps_pulls _ _) ?_; rintro c1 ⟨kept, -⟩
        exact Ok.ok.mpr (distinct_of_same_names distinct_c (kept_names kept))
      · exact Ok.ok.mpr distinct_c

/-- The loop of `failed` over the pulls whose try fails (`try_failed` for each) keeps the names
distinct. -/
theorem failed_loop0_distinct (iter : alloc.vec.into_iter.IntoIter Std.U32) (c : Core)
    (now : Std.U64) (cl : Class) (out : alloc.vec.Vec Action) (distinct_c : distinct c) :
    Ok (failed_loop0 iter c now cl out) (fun r => distinct r.1) := by
  unfold failed_loop0
  refine Ok.loop (I := fun x => distinct x.2.1) ?_ distinct_c
  rintro ⟨it, c1, out1⟩ so_far
  dsimp only at so_far
  unfold failed_loop0.body
  refine Ok.bind (into_iter_next _) ?_
  rintro ⟨o, it1⟩ (⟨rfl, _⟩ | ⟨other, rest, rfl, cons, is_rest⟩)
  · exact Ok.ok.mpr so_far
  · refine Ok.bind (pull_at_sound c1 other) ?_
    intro o1 found
    cases o1 with
    | none => exact Ok.ok.mpr so_far
    | some at_ =>
      simp only []
      refine Ok.bind (try_failed_distinct c1 now at_ cl out1 so_far) ?_
      rintro ⟨c2, out2⟩ distinct2
      exact Ok.ok.mpr distinct2

/-- `failed` keeps the names distinct. -/
theorem failed_distinct (c : Core) (now : Std.U64) (work : Work) (cl : Class)
    (out : alloc.vec.Vec Action) (distinct_c : distinct c) :
    Ok (failed c now work cl out) (fun r => distinct r.1) := by
  unfold failed
  cases work with
  | Pull pull =>
    refine Ok.bind (pull_at_sound c pull) ?_
    intro o found
    cases o with
    | none => exact Ok.ok.mpr distinct_c
    | some at_ =>
      obtain ⟨in_range, named⟩ := found at_ rfl
      simp only []
      rw [index_in_range _ _ in_range]
      simp only [bind_ok]
      split
      · exact Ok.ok.mpr distinct_c
      · -- the try of the pull fails
        simp only [lift, bind_ok]
        refine Ok.bind (Ok.any _) ?_; intro it _
        exact failed_loop0_distinct it _ now cl out (distinct_of_same_names distinct_c rfl)
      · exact Ok.ok.mpr distinct_c
      · exact leave_distinct c at_ out distinct_c
  | Layer layer =>
    refine Ok.bind (Ok.any _) ?_; intro o _
    cases o with
    | none => exact Ok.ok.mpr distinct_c
    | some l =>
      simp only []
      refine Ok.bind (Ok.any _) ?_; intro l1 _
      refine Ok.bind (Ok.any _) ?_; intro b _
      split
      · exact Ok.ok.mpr distinct_c
      · refine Ok.bind (Ok.any _) ?_; rintro ⟨l2, back⟩ _
        simp only [uncurry_eq]
        refine Ok.bind (Ok.any _) ?_; intro s _
        refine Ok.bind (Ok.any _) ?_; intro failing _
        refine Ok.bind (Ok.any _) ?_; intro it _
        rw [failed_loops_are_the_same.1]
        exact failed_loop0_distinct it _ now cl out (distinct_of_same_names distinct_c rfl)
  | Group group =>
    refine Ok.bind (Ok.any _) ?_; intro o _
    cases o with
    | none => exact Ok.ok.mpr distinct_c
    | some g =>
      simp only []
      refine Ok.bind (Ok.any _) ?_; intro g1 _
      refine Ok.bind (Ok.any _) ?_; intro b _
      split
      · refine Ok.bind (Ok.any _) ?_; rintro ⟨g2, back⟩ _
        simp only [uncurry_eq]
        refine Ok.bind (Ok.any _) ?_; intro g3 _
        refine Ok.bind (Ok.any _) ?_; intro failing _
        refine Ok.bind (Ok.any _) ?_; intro it _
        rw [failed_loops_are_the_same.2]
        exact failed_loop0_distinct it _ now cl out (distinct_of_same_names distinct_c rfl)
      · exact Ok.ok.mpr distinct_c

/-- `prepared` keeps the names distinct: a late answer only pushes, an answer in time changes
the layers and the phase of one pull. -/
theorem prepared_distinct (c : Core) (pull : Std.U32) (layers : alloc.vec.Vec Std.U32)
    (groups : alloc.vec.Vec GroupFact) (out : alloc.vec.Vec Action) (distinct_c : distinct c) :
    Ok (prepared c pull layers groups out) (fun r => distinct r.1) := by
  unfold prepared
  refine Ok.bind (Ok.any _) ?_; intro o _
  refine Ok.bind (filter_preparing c o) ?_; intro at1 preparing
  refine Ok.bind (Ok.any _) ?_; intro fresh _
  refine Ok.bind (Ok.any _) ?_; intro fresh1 _
  cases at1 with
  | none =>
    -- a late answer: the layers and the groups it named are told back
    refine Ok.bind (Ok.any _) ?_; intro iter _
    refine Ok.bind (Ok.any _) ?_; intro out1 _
    refine Ok.bind (Ok.any _) ?_; intro iter1 _
    refine Ok.bind (Ok.any _) ?_; intro out2 _
    exact Ok.ok.mpr distinct_c
  | some at2 =>
    obtain ⟨in_range, is_preparing⟩ := preparing at2 rfl
    refine Ok.bind (Ok.any _) ?_; intro iter _
    refine Ok.bind (Ok.any _) ?_; rintro ⟨v, out1⟩ _
    simp only [uncurry_eq]
    refine Ok.bind (Ok.any _) ?_; intro iter1 _
    refine Ok.bind (Ok.any _) ?_; intro v1 _
    -- the pull gets its layers and works
    refine Ok.bind (index_mut_result _ _) ?_
    rintro _ ⟨in_range1, rfl⟩
    simp only [uncurry_eq]
    refine Ok.bind (index_mut_result _ _) ?_
    rintro _ ⟨in_range2, rfl⟩
    simp only [uncurry_eq]
    exact Ok.ok.mpr (distinct_of_set distinct_c at2.val
      { c.pulls.val[at2.val] with layers := layers, phase := Phase.Running Step.Working }
      in_range rfl (by simp [alloc.vec.Vec.set]))

/-- The loop of a `Tick` over the pulls begins the try of the pulls that wait: it keeps the
names distinct. -/
theorem step_loop_distinct (iter : core.ops.range.Range Std.Usize) (c : Core) (now : Std.U64)
    (out : alloc.vec.Vec Action) (distinct_c : distinct c) :
    Ok (step_loop iter c now out) (fun r => distinct r.1) := by
  unfold step_loop
  refine Ok.loop (I := fun x => distinct x.2.1) ?_ distinct_c
  rintro ⟨iter, c1, out1⟩ so_far
  dsimp only at so_far
  unfold step_loop.body
  refine Ok.bind (Ok.any _) ?_; rintro ⟨o, iter1⟩ _
  simp only [uncurry_eq]
  cases o with
  | none => exact Ok.ok.mpr so_far
  | some at_ =>
    simp only []
    refine Ok.bind (index_result _ _) ?_; rintro _ ⟨in_range, rfl⟩
    split
    · exact Ok.ok.mpr so_far
    · exact Ok.ok.mpr so_far
    · split
      · -- the wait is over: the try begins
        refine Ok.bind (begin_try_distinct c1 at_ out1 so_far) ?_
        rintro ⟨c2, out2⟩ distinct2
        exact Ok.ok.mpr distinct2
      · exact Ok.ok.mpr so_far
    · exact Ok.ok.mpr so_far

/-- **The names stay distinct** (the statement of Spec.lean): each event is a call of one
function of lib.rs (then `advance`), or code of `step` itself (`Step.lean`), and each piece keeps
the names distinct. -/
theorem the_names_stay_distinct : TheNamesStayDistinct := by
  intro c now ev out c' out' distinct_c returns
  have boosted : ∀ (at_ : Std.Usize) (in_range : at_.val < c.pulls.val.length),
      distinct (hurried c at_ in_range) := fun at_ in_range =>
    distinct_of_set distinct_c at_.val { c.pulls.val[at_.val] with boosted := true } in_range rfl
      (set_val _ _ _)
  have kept : Ok (step c now ev out) (fun r => distinct r.1) :=
    StepFacts.holds (told := fun _ => True) (A := fun r => distinct r.1) (Q := fun r => distinct r.1)
      { advance_ok := fun r d => advance_distinct r.1 now r.2 d
        add_ok := fun pull containers => add_distinct c pull containers out distinct_c
        cancel_ok := fun pull => cancel_distinct c pull out distinct_c
        prepared_ok := fun pull layers groups _ =>
          prepared_distinct c pull layers groups out distinct_c
        succeeded_ok := fun work => succeeded_distinct c work out distinct_c
        failed_ok := fun work cl => failed_distinct c now work cl out distinct_c
        hurry_of_none := distinct_c
        hurry_boosts := boosted
        hurry_begins := fun at_ in_range _ => begin_try_distinct _ _ _ (boosted at_ in_range)
        start_of_a_layer := fun layer => (start_at_keeps_pulls c layer now).mono
          fun _ same_pulls _ => distinct_of_same_names distinct_c (by rw [(same_pulls _).1])
        wake := fun _ d _ _ _ => d
        tick_loop := fun iter => step_loop_distinct iter c now out distinct_c } ev trivial
  exact kept.eq returns

/-- **A new core has no pull** (the statement of Spec.lean), so its names are distinct. -/
theorem a_new_core_has_no_pull : ANewCoreHasNoPull := by
  intro cfg c made
  have no_pull : Ok (Core.new cfg) (fun c => c.pulls.val = []) := by
    unfold Core.new
    exact Ok.ok.mpr rfl
  exact no_pull.eq made

end LazyCore
