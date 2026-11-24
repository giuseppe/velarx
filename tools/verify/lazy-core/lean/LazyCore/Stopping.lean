-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proof of `AStoppingPullOnlyEnds` and
-- `TheEndOfTheStopEndsIt` (Spec.lean).  A pull `p` that is `Cancelling`
-- (`cancel` asked `Abort (Pull p)`) is only waiting for the end of what ran
-- for it.  Whatever event comes, `step` asks nothing about it but `End p`,
-- the pull stays `Cancelling` until it is removed, it is removed only with
-- `End p`, and when `End p` is asked it is gone; and the answer
-- `Done (Pull p) _` removes it.
--
-- The file is the chain of one fact per function of lib.rs, each after the
-- functions it calls (so, from the bottom of lib.rs up: `begin_try`,
-- `let_go`, `leave` with its loop, `try_failed`, `advance`, `add`, `cancel`
-- with its loop, `succeeded`, `failed` with its loop, `prepared`, the loop of
-- a `Tick`, and last `step`, whose walk of the events is Step.lean).  What is not about stopping (the search
-- `pull_at`, the facts of `Vec` and of the loops, `Kept`) is in Pulls.lean,
-- Verdict.lean and Grows.lean.  The argument, in four sentences:
--   1. The fact of a function, for a fixed `p`: if the names of the pulls
--      are distinct and every pull named `p` is `Cancelling` (`Stopping`),
--      the function keeps both, appends only actions that `OnlyEnds` allows
--      for `p` (not about `p`, or `End p`), never makes a pull named `p`, does
--      not lose `p` without asking `End p`, and after `End p` the core holds no
--      `p`.  That fact is `KeepsStopping`.
--   2. `KeepsStopping` composes (`KeepsStopping.trans`): a function body is
--      a chain of calls, so the fact of a function follows from those of the
--      functions it calls.
--   3. A function that begins a try, records a state or asks `Abort`/
--      `CommitImage`/`DriverPull` of a pull has a side condition: the pull
--      is not named `p`.  The callers give it, each in its own way:
--        - `Hurry` (in `step`), the loop of a `Tick` and the loop of `leave`
--          begin tries of pulls that are queued or waiting, and a pull
--          named `p` is `Cancelling`;
--        - `try_failed` is called for the one pull that runs, or for the
--          pulls `Core::lacking` returns, which are working;
--        - `cancel` pushes `Abort` of a pull that runs, and lets go of the
--          pulls that lack its layers, which are working;
--        - `advance` asks only for working pulls; `prepared` changes only a
--          pull that is `Running Preparing`; `add` pushes a new pull, and a
--          pull named `p` is not added, since the core holds `p`.
--      A `Cancelling` pull is none of these.  What `let_go` and `advance`
--      push for layers and groups says nothing of any pull
--      (`AppendsAboutNoPull`, in Grows.lean).
--   4. The first claim is `KeepsStopping` of `step` read at the end.  The
--      second is `Done (Pull p)`: `succeeded` and `failed` find the pull by
--      name (the names are distinct) and `leave` it, which asks `End p` and
--      removes it, and `advance` keeps the names.
--
-- Read before this file: Ok.lean, Grows.lean, Pulls.lean, Verdict.lean, Names.lean, Step.lean
-- (the names stay distinct: `KeepsStopping` repeats it, for the intermediate
-- cores, with the help of the small facts of Names.lean), and the two statements
-- in Spec.lean.
--
-- Notation: besides the notations of the files above,
--   - `KeepsStopping p c out r` is the fact of point 1 for a function that
--     was given the core `c` and the actions `out` and returned `r`;
--   - `Ok m P` is "if `m` returns, its result satisfies `P`" (Ok.lean);
--   - `c.pulls.val` is the list of the pulls of `c`; `l ++ t` joins lists;
--     `a ∈ t` is "`a` is in `t`"; `∃ t, ...` is "there is a `t` such that".
import LazyCore.Names

open Aeneas Aeneas.Std Result velarx_lazy_core

namespace LazyCore

attribute [local irreducible] begin_try let_go_loop0 let_go_loop1 let_go leave_loop leave
  cancel_loop cancel advance_loop2 advance_loop3 advance_loop4_loop0 advance_loop4 advance
  Core.pull_at Core.lacking slots_held goes wanting in_flight Core.starting Pull.has_all
  Pull.working Pull.wants Pull.lacks

/-- Every pull named `p` is being stopped (there may be none). -/
def Stopping (p : Std.U32) (c : Core) : Prop :=
  ∀ q ∈ c.pulls.val, q.id = p → q.phase = Phase.Cancelling

/-- The action does no harm to a pull `p` that is being stopped: it says nothing of `p`,
or it is `End p`. -/
def OnlyEnds (p : Std.U32) (a : Action) : Prop :=
  about a p → a = Action.End p

/-- What a function of lib.rs does when the pull `p` is being stopped (`Stopping`): from the
core `c` and the actions `out` it makes `r`, with the names still distinct and `p` still
stopping, and it appends to `out` only actions that `OnlyEnds` allows for `p`.  And for the
pull `p` itself: if it was held, it still is or `End p` was appended; it is held after only
if it was before (no function makes a pull named `p`); and if `End p` was appended, it is
not held after. -/
def KeepsStopping (p : Std.U32) (c : Core) (out : alloc.vec.Vec Action)
    (r : Core × alloc.vec.Vec Action) : Prop :=
  distinct r.1 ∧ Stopping p r.1 ∧ ∃ t, r.2.val = out.val ++ t ∧ (∀ a ∈ t, OnlyEnds p a) ∧
    (held c p → held r.1 p ∨ Action.End p ∈ t) ∧ (held r.1 p → held c p) ∧
    (Action.End p ∈ t → ¬ held r.1 p)

/-- Two functions one after the other, each `KeepsStopping`, are `KeepsStopping` together. -/
theorem KeepsStopping.trans {p : Std.U32} {c : Core} {out : alloc.vec.Vec Action}
    {r1 r2 : Core × alloc.vec.Vec Action}
    (first : KeepsStopping p c out r1) (second : KeepsStopping p r1.1 r1.2 r2) :
    KeepsStopping p c out r2 := by
  obtain ⟨_, _, t1, pushed1, only_ends1, held1, gained1, end_gone1⟩ := first
  obtain ⟨distinct2, stopping2, t2, pushed2, only_ends2, held2, gained2, end_gone2⟩ := second
  refine ⟨distinct2, stopping2, t1 ++ t2, by rw [pushed2, pushed1, List.append_assoc], ?_, ?_,
    fun held_after => gained1 (gained2 held_after), ?_⟩
  · intro a ha
    rcases List.mem_append.mp ha with ha | ha
    exacts [only_ends1 a ha, only_ends2 a ha]
  · intro held_c
    rcases held1 held_c with still | ended
    · rcases held2 still with still | ended
      exacts [Or.inl still, Or.inr (List.mem_append_right _ ended)]
    · exact Or.inr (List.mem_append_left _ ended)
  · intro end_in held_after
    rcases List.mem_append.mp end_in with end_in | end_in
    · exact end_gone1 end_in (gained2 held_after)
    · exact end_gone2 end_in held_after

/-- A function that does nothing keeps everything. -/
theorem KeepsStopping.refl {p : Std.U32} {c : Core} (out : alloc.vec.Vec Action)
    (distinct_c : distinct c) (stopping : Stopping p c) : KeepsStopping p c out (c, out) :=
  ⟨distinct_c, stopping, [], by simp, by simp, fun held_c => Or.inl held_c, id, by simp⟩

/-- A function that leaves the list of the names as it was, leaves `p` stopping, and appends
only actions that are not about `p`, `KeepsStopping`. -/
theorem KeepsStopping.of_same_names {p : Std.U32} {c : Core} (c' : Core)
    (out out' : alloc.vec.Vec Action) (t : List Action) (distinct_c : distinct c)
    (same_names : c'.pulls.val.map (·.id) = c.pulls.val.map (·.id)) (stopping' : Stopping p c')
    (pushed : out'.val = out.val ++ t) (not_about_p : ∀ a ∈ t, ¬ about a p) :
    KeepsStopping p c out (c', out') := by
  have held_same : held c' p ↔ held c p := by rw [held_iff_name, held_iff_name, same_names]
  exact ⟨distinct_of_same_names distinct_c same_names, stopping', t, pushed,
    fun a ha about_p => absurd about_p (not_about_p a ha),
    fun held_c => Or.inl (held_same.mpr held_c),
    held_same.mp, fun end_in => absurd (by simp [about]) (not_about_p _ end_in)⟩

/-- A function that changes only the pull at `i`, to `q` of the same name that is not
a pull named `p` unless it is being stopped, and appends only actions that are not about `p`,
`KeepsStopping`. -/
theorem KeepsStopping.of_set {p : Std.U32} {c : Core} (c' : Core) (out out' : alloc.vec.Vec Action)
    (i : Nat) (q : Pull) (distinct_c : distinct c) (stopping : Stopping p c)
    (in_range : i < c.pulls.val.length) (same_id : q.id = (c.pulls.val[i]).id)
    (still_stopping : q.id = p → q.phase = Phase.Cancelling)
    (pulls' : c'.pulls.val = c.pulls.val.set i q) (t : List Action)
    (pushed : out'.val = out.val ++ t) (not_about_p : ∀ a ∈ t, ¬ about a p) :
    KeepsStopping p c out (c', out') := by
  refine KeepsStopping.of_same_names c' out out' t distinct_c ?_ ?_ pushed not_about_p
  · rw [pulls']; exact map_set_of_same (·.id) _ _ _ in_range same_id
  · intro x hx named_p
    rw [pulls'] at hx
    rcases List.mem_or_eq_of_mem_set hx with in_c | rfl
    · exact stopping x in_c named_p
    · exact still_stopping named_p

/-- `begin_try` of the pull at `at_`, when that pull is not named `p`, is `KeepsStopping`:
it pushes `Record` and `Prepare` of that pull. -/
theorem begin_try_keeps_stopping (p : Std.U32) (c : Core) (at_ : Std.Usize)
    (out : alloc.vec.Vec Action)
    (distinct_c : distinct c) (stopping : Stopping p c)
    (not_p : ∀ h : at_.val < c.pulls.val.length, (c.pulls.val[at_.val]).id ≠ p) :
    Ok (begin_try c at_ out) (KeepsStopping p c out) := by
  unfold begin_try
  refine Ok.bind (index_mut_result _ _) ?_
  rintro _ ⟨in_range, rfl⟩
  simp only [uncurry_eq]
  refine Ok.bind (push_appends _ _) ?_; intro out1 pushed_record
  refine Ok.bind (push_appends _ _) ?_; intro out2 pushed_prepare
  apply Ok.ok.mpr
  have not_named_p := not_p in_range
  refine KeepsStopping.of_set _ _ _ _
    { c.pulls.val[at_.val] with phase := Phase.Running Step.Preparing, progressed := false }
    distinct_c stopping in_range rfl
    (fun named_p => absurd named_p not_named_p) ?_
    (out2.val.drop out.val.length)
    (by rw [pushed_prepare, pushed_record]; simp) ?_
  · simp [alloc.vec.Vec.set]
  · -- the two actions pushed, in whichever order, are of the pull at `at_`
    intro a ha
    rw [pushed_prepare, pushed_record] at ha
    simp only [List.append_assoc, List.drop_left', List.mem_append, List.mem_singleton] at ha
    rcases ha with rfl | rfl <;> exact fun named_p => absurd named_p not_named_p

/-- `let_go` of the pull at `at_` is `KeepsStopping`: it changes only the layers of that pull, and
pushes only actions that say nothing of a pull. -/
theorem let_go_keeps_stopping (p : Std.U32) (c : Core) (at_ : Std.Usize)
    (out : alloc.vec.Vec Action)
    (distinct_c : distinct c) (stopping : Stopping p c) :
    Ok (let_go c at_ out) (KeepsStopping p c out) := by
  refine (let_go_changes_layers c at_ out).mono ?_
  rintro r ⟨no_pull, _, in_range, ls, pulls⟩
  obtain ⟨t, pushed, none_about⟩ := no_pull.appended
  refine KeepsStopping.of_set r.1 out r.2 at_.val { c.pulls.val[at_.val] with layers := ls }
    distinct_c stopping in_range rfl ?_ (by simp [pulls, alloc.vec.Vec.set]) t pushed
    fun a ha => none_about a ha p
  exact fun named_p => stopping (c.pulls.val[at_.val]) (List.getElem_mem in_range) named_p

/-- The loop of `leave` that gives the freed place to the pulls that wait is `KeepsStopping`: it
calls `begin_try` only for pulls that are queued, so not for a pull named `p`. -/
theorem leave_loop_keeps_stopping (p : Std.U32) (iter : core.ops.range.Range Std.Usize) (c : Core)
    (out : alloc.vec.Vec Action) (distinct_c : distinct c) (stopping : Stopping p c) :
    Ok (leave_loop iter c out) (KeepsStopping p c out) := by
  unfold leave_loop
  refine Ok.loop (I := fun x => KeepsStopping p c out (x.2.1, x.2.2)) ?_
    (KeepsStopping.refl _ distinct_c stopping)
  rintro ⟨iter, c1, out1⟩ so_far
  dsimp only at so_far
  unfold leave_loop.body
  -- the next index of the range: `for at in 0..c.pulls.len()`
  refine Ok.bind (Ok.any _) ?_; rintro ⟨o, iter1⟩ _
  simp only [uncurry_eq]
  cases o with
  | none => exact Ok.ok.mpr so_far
  | some at_ =>
    simp only []
    -- `if slots_held(c) >= completers { break }`
    refine Ok.bind (Ok.any _) ?_; intro i _
    split
    · exact Ok.ok.mpr so_far
    · -- `if c.pulls[at].phase == Phase::Queued`
      refine Ok.bind (index_result _ _) ?_; rintro _ ⟨in_range, rfl⟩
      refine Ok.bind (phase_eq_true _ Phase.Queued) ?_; intro is_queued queued_if
      split
      · -- it is queued: it gets the place (`slot = true`), and `begin_try` runs for it
        have queued := queued_if (by assumption)
        refine Ok.bind (index_mut_result _ _) ?_
        rintro _ ⟨in_range, rfl⟩
        simp only [uncurry_eq]
        have got_the_place := KeepsStopping.of_set (p := p)
          { c1 with pulls := (alloc.vec.Vec.set c1.pulls at_
            { c1.pulls.val[at_.val] with slot := true }) }
          out1 out1 at_.val { c1.pulls.val[at_.val] with slot := true } so_far.1 so_far.2.1
          in_range rfl
          (fun named_p => by
            have := so_far.2.1 _ (List.getElem_mem in_range) named_p
            rw [queued] at this; cases this)
          (by simp [alloc.vec.Vec.set]) [] (by simp) (by simp)
        refine Ok.bind
          (begin_try_keeps_stopping p _ at_ out1 got_the_place.1 got_the_place.2.1 ?_) ?_
        · intro h named_p
          have := so_far.2.1 _ (List.getElem_mem in_range)
            (by simpa [alloc.vec.Vec.set] using named_p)
          simp [queued] at this
        · rintro ⟨c2, out2⟩ began
          exact Ok.ok.mpr (so_far.trans (got_the_place.trans began))
      · exact Ok.ok.mpr so_far

/-- `leave` of the pull at `at_` is `KeepsStopping`, whatever the pull: it lets go, removes the
pull, pushes `End` of it (only_ends for every `p`; if the pull is named `p`, that is the `End p`
the claim wants), and gives the place away. -/
theorem leave_keeps_stopping (p : Std.U32) (c : Core) (at_ : Std.Usize) (out : alloc.vec.Vec Action)
    (distinct_c : distinct c) (stopping : Stopping p c) :
    Ok (leave c at_ out) (KeepsStopping p c out) := by
  unfold leave
  -- `let_go` first: it changes only the layers of the pull
  refine Ok.bind ((let_go_changes_layers c at_ out).and
    (let_go_keeps_stopping p c at_ out distinct_c stopping)) ?_
  rintro ⟨c1, out1⟩ ⟨⟨_, _, in_range, ls, pulls1⟩, let_go_did⟩
  dsimp only at pulls1
  simp only [uncurry_eq]
  have in_range1 : at_.val < c1.pulls.val.length := by
    rw [pulls1]; simpa [alloc.vec.Vec.set] using in_range
  have same_name : (c1.pulls.val[at_.val]).id = (c.pulls.val[at_.val]).id := by
    simp [pulls1, alloc.vec.Vec.set]
  -- then the pull is removed (`c.pulls.remove(at)`) and `End` of it is pushed
  obtain ⟨rest, removed, rest_is⟩ := remove_returns_and_erases c1.pulls at_ in_range1
  rw [removed]
  simp only [bind_ok, uncurry_eq]
  refine Ok.bind (push_appends _ _) ?_; intro out2 pushed_end
  have removed_the_pull : KeepsStopping p c1 out1 ({ c1 with pulls := rest }, out2) := by
    obtain ⟨distinct1, stopping1, _⟩ := let_go_did
    have not_in_rest := name_not_in_others c1.pulls.val distinct1 at_.val in_range1
    refine ⟨?_, ?_, [Action.End (c1.pulls.val[at_.val]).id], pushed_end, ?_, ?_, ?_, ?_⟩
    · unfold distinct
      dsimp only
      rw [rest_is]
      exact List.Nodup.sublist ((List.eraseIdx_sublist _ _).map _) distinct1
    · intro x hx
      exact stopping1 x ((List.eraseIdx_sublist _ _).subset (rest_is ▸ hx))
    · intro a ha
      simp only [List.mem_singleton] at ha
      subst ha
      exact fun named => congrArg Action.End named
    · rintro ⟨q, hq, named_p⟩
      obtain ⟨j, hj, rfl⟩ := List.getElem_of_mem hq
      by_cases same : j = at_.val
      · subst same; exact Or.inr (by simp [named_p])
      · have in_rest : c1.pulls.val[j] ∈ rest.val := by
          rw [rest_is]; exact List.mem_eraseIdx_iff_getElem.mpr ⟨j, hj, same, rfl⟩
        exact Or.inl ⟨_, in_rest, named_p⟩
    · -- a pull of the rest was there before
      rintro ⟨q, hq, named_p⟩
      exact ⟨q, (List.eraseIdx_sublist _ _).subset (rest_is ▸ hq), named_p⟩
    · -- `End p` is `End` of the pull that was removed, and no other pull has its name
      intro end_in ⟨q, hq, named_p⟩
      have same_id : (c1.pulls.val[at_.val]).id = p := by
        injection List.mem_singleton.mp end_in with same
        exact same.symm
      refine not_in_rest (same_id ▸ ?_)
      rw [← rest_is]
      exact List.mem_map.mpr ⟨q, hq, named_p⟩
  -- and the loop that gives the place away is `KeepsStopping` for the pulls that are left
  refine (leave_loop_keeps_stopping p _ _ out2 removed_the_pull.1 removed_the_pull.2.1).mono ?_
  intro r gave_the_place
  exact let_go_did.trans (removed_the_pull.trans gave_the_place)

/-- A push of actions that are not about `p`, to the end of `out`, is `KeepsStopping` (the core
is as it was). -/
theorem KeepsStopping.push {p : Std.U32} {c : Core} {out out' : alloc.vec.Vec Action}
    {t : List Action} (distinct_c : distinct c) (stopping : Stopping p c)
    (pushed : out'.val = out.val ++ t) (not_about_p : ∀ a ∈ t, ¬ about a p) :
    KeepsStopping p c out (c, out') :=
  KeepsStopping.of_same_names c out out' t distinct_c rfl stopping pushed not_about_p

/-- One action that is not about `p` is a list of them. -/
theorem not_about_single {p : Std.U32} {a : Action} (not_about_p : ¬ about a p) :
    ∀ b ∈ [a], ¬ about b p := by
  intro b hb
  rw [List.mem_singleton.mp hb]
  exact not_about_p

/-- `try_failed` of the pull at `at_`, when that pull is not named `p`, is `KeepsStopping`: it
records
a state of that pull, and either `leave`s it or lets go of its layers and asks to be woken. -/
theorem try_failed_keeps_stopping (p : Std.U32) (c : Core) (now : Std.U64) (at_ : Std.Usize)
    (cl : Class) (out : alloc.vec.Vec Action) (distinct_c : distinct c) (stopping : Stopping p c)
    (not_p : ∀ h : at_.val < c.pulls.val.length, (c.pulls.val[at_.val]).id ≠ p) :
    Ok (try_failed c now at_ cl out) (KeepsStopping p c out) := by
  unfold try_failed
  -- the pull is taken, its failures counted, and the state of the failure decided
  refine Ok.bind (index_mut_result _ _) ?_
  rintro _ ⟨in_range, rfl⟩
  simp only [uncurry_eq]
  have not_named_p := not_p in_range
  refine Ok.bind (Ok.any _) ?_; intro failures _
  refine Ok.bind (Ok.any _) ?_; rintro ⟨cfg, failures1, state⟩ _
  -- `Record` of the state is pushed, and the pull put back, with another phase or failures
  refine Ok.bind (push_appends _ _) ?_; intro out1 pushed_record
  have recorded : ∀ q : Pull, q.id = (c.pulls.val[at_.val]).id →
      KeepsStopping p c out
        ({ c with cfg := cfg, pulls := alloc.vec.Vec.set c.pulls at_ q }, out1) := by
    intro q same_id
    refine KeepsStopping.of_set _ out out1 at_.val q distinct_c stopping in_range same_id
      (fun named_p => absurd (same_id ▸ named_p) not_named_p) (by simp [alloc.vec.Vec.set])
      [Action.Record (c.pulls.val[at_.val]).id state] pushed_record ?_
    intro a ha
    rw [List.mem_singleton] at ha
    subst ha
    exact fun named_p => absurd named_p not_named_p
  -- the try is over (the arm `_ => leave(c, at, out)` of `match state`): the pull is put back
  -- with its failures counted, and `leave` ends it
  have over : ∀ q : Pull, q = { c.pulls.val[at_.val] with failures := failures1 } →
      Ok (leave { c with cfg := cfg, pulls := alloc.vec.Vec.set c.pulls at_ q } at_ out1)
        (KeepsStopping p c out) := by
    intro q is_q
    have put_back := recorded q (by rw [is_q])
    refine (leave_keeps_stopping p _ at_ out1 put_back.1 put_back.2.1).mono ?_
    exact fun r ended => put_back.trans ended
  -- the try waits (the arm `Backoff(until) | NoSpace(until)`): the pull is put back as
  -- waiting, `let_go` lets go of its layers, and `Wake(until)` is pushed
  have waits : ∀ (wake : Std.U64) (q : Pull),
      q = { c.pulls.val[at_.val] with phase := Phase.Waiting wake, failures := failures1 } →
      Ok (do
        let (c2, out2) ← let_go
          { c with cfg := cfg, pulls := alloc.vec.Vec.set c.pulls at_ q } at_ out1
        let out3 ← alloc.vec.Vec.push out2 (Action.Wake wake)
        ok (c2, out3)) (KeepsStopping p c out) := by
    intro wake q is_q
    have put_back := recorded q (by rw [is_q])
    refine Ok.bind (let_go_keeps_stopping p _ at_ out1 put_back.1 put_back.2.1) ?_
    rintro ⟨c2, out2⟩ let_go_did
    refine Ok.bind (push_appends _ _) ?_; intro out3 pushed_wake
    exact Ok.ok.mpr (put_back.trans (let_go_did.trans (KeepsStopping.push let_go_did.1
      let_go_did.2.1 pushed_wake (not_about_single fun named => nomatch named))))
  -- the state decides, as the Rust `match state` does
  rcases state with _ | _ | wait | wait | _ | _
  · exact over _ rfl   -- `Queued`: not given by `match class`, falls in `_ => leave`
  · exact over _ rfl   -- `Running`: the same
  · exact waits wait _ rfl   -- `Backoff(until)`
  · exact waits wait _ rfl   -- `NoSpace(until)`
  · exact over _ rfl   -- `NeedsCredentials`
  · exact over _ rfl   -- `Failed`

/-- A function that leaves every pull `Kept` and appends only actions that are not about `p`
is `KeepsStopping`: a pull named `p` is not working (it is being stopped), so it is as it was. -/
theorem KeepsStopping.of_kept {p : Std.U32} {c : Core} (c' : Core)
    (out out' : alloc.vec.Vec Action) (t : List Action) (distinct_c : distinct c)
    (stopping : Stopping p c) (kept : List.Forall₂ Kept c.pulls.val c'.pulls.val)
    (pushed : out'.val = out.val ++ t) (not_about_p : ∀ a ∈ t, ¬ about a p) :
    KeepsStopping p c out (c', out') := by
  refine KeepsStopping.of_same_names c' out out' t distinct_c (kept_names kept) ?_ pushed
    not_about_p
  intro x hx named_p
  obtain ⟨y, hy, kept_y⟩ := forall₂_mem_right kept hx
  have y_stopping := stopping y hy (kept_y.1.symm.trans named_p)
  exact (kept_y.2.1 (by rw [y_stopping]; simp)).trans y_stopping

/-- `advance` is `KeepsStopping`: it keeps the names, a pull that is being stopped is not working so
it is not touched, and what `advance` asks for is asked for working pulls only. -/
theorem advance_keeps_stopping (p : Std.U32) (c : Core) (now : Std.U64) (out : alloc.vec.Vec Action)
    (distinct_c : distinct c) (stopping : Stopping p c) :
    Ok (advance c now out) (KeepsStopping p c out) := by
  refine (advance_keeps_pulls c now out).mono ?_
  rintro r ⟨⟨t, pushed, asked⟩, kept, _⟩
  refine KeepsStopping.of_kept r.1 out r.2 t distinct_c stopping kept pushed ?_
  intro a ha
  rcases asked a ha with none_about | ⟨y, hy, working, rfl | rfl⟩
  · exact none_about p
  all_goals
    intro named_p
    have := stopping y hy named_p
    rw [working] at this; cases this

/-- `add` of a pull is `KeepsStopping` when the core holds `p` (so `add` does not make a new
pull named `p` that is not being stopped): it pushes a new, queued pull, and begins its try
or records that it is queued. -/
theorem add_keeps_stopping (p : Std.U32) (c : Core) (pull : Std.U32) (containers : Bool)
    (out : alloc.vec.Vec Action) (distinct_c : distinct c) (stopping : Stopping p c)
    (held_p : held c p) : Ok (add c pull containers out) (KeepsStopping p c out) := by
  unfold add
  -- the pull is looked up: if it is there, nothing is done
  refine Ok.bind (pull_at_none c pull) ?_; intro o none_not_held
  cases o with
  | some n => exact Ok.ok.mpr (KeepsStopping.refl _ distinct_c stopping)
  | none =>
  have not_held := none_not_held rfl
  have not_p : pull ≠ p := fun same => not_held (same ▸ held_p)
  -- the new pull is queued and has a new name
  have added : ∀ (v : alloc.vec.Vec Pull) (q : Pull), q.id = pull → q.phase = Phase.Queued →
      v.val = c.pulls.val ++ [q] → KeepsStopping p c out ({ c with pulls := v }, out) := by
    intro v q named queued v_is
    have not_in_names : pull ∉ c.pulls.val.map (·.id) := fun h => not_held (held_iff_name.mpr h)
    refine ⟨?_, ?_, [], by simp, by simp, fun held_c => Or.inl ?_, fun _ => held_p, by simp⟩
    · exact distinct_of_push distinct_c v q v_is (named ▸ not_in_names)
    · intro x hx named_p
      rw [v_is] at hx
      rcases List.mem_append.mp hx with hx | hx
      · exact stopping x hx named_p
      · rw [List.mem_singleton.mp hx] at named_p
        exact absurd (named.symm.trans named_p) not_p
    · rw [held_iff_name] at held_c ⊢
      dsimp only
      rw [v_is]
      simp [held_c]
  -- the try begins (`begin_try` of the last pull), or the pull is recorded as queued
  have began : ∀ (v : alloc.vec.Vec Pull) (q : Pull), q.id = pull → q.phase = Phase.Queued →
      v.val = c.pulls.val ++ [q] →
      Ok (do let i2 ← (alloc.vec.Vec.len v - 1#usize)
             begin_try { c with pulls := v } i2 out) (KeepsStopping p c out) := by
    intro v q named queued v_is
    have got_in := added v q named queued v_is
    refine Ok.bind (pred_len _) ?_
    intro i2 last
    refine (begin_try_keeps_stopping p _ i2 out got_in.1 got_in.2.1 ?_).mono
      fun r began => got_in.trans began
    · intro h named_p
      have : i2.val = c.pulls.val.length := by
        rw [alloc.vec.Vec.len_val] at last; simp [v_is] at last; omega
      have at_end : (({ c with pulls := v } : Core).pulls.val[i2.val]) = q := by
        simp [v_is, this]
      rw [at_end] at named_p
      exact not_p (named.symm.trans named_p)
  have recorded : ∀ (v : alloc.vec.Vec Pull) (q : Pull), q.id = pull → q.phase = Phase.Queued →
      v.val = c.pulls.val ++ [q] →
      Ok (do let out1 ← alloc.vec.Vec.push out (Action.Record pull State.Queued)
             ok ({ c with pulls := v }, out1)) (KeepsStopping p c out) := by
    intro v q named queued v_is
    have got_in := added v q named queued v_is
    refine Ok.bind (push_appends _ _) ?_; intro out1 pushed
    exact Ok.ok.mpr (got_in.trans (KeepsStopping.push got_in.1 got_in.2.1 pushed
      (not_about_single fun named_p => absurd named_p not_p)))
  simp only [core.option.Option.is_some, Option.isSome_none, Bool.false_eq_true, ↓reduceIte]
  -- `slots_held(c) < completers`: is there a free place?
  refine Ok.bind (Ok.any _) ?_; intro i _
  by_cases free : i < c.cfg.completers
  · -- yes: the pull is pushed (it takes the place unless it is for a container), and
    -- `if free || containers { begin_try }` begins its try
    simp only [free, ↓reduceIte]
    refine Ok.bind (push_appends _ _) ?_; intro v pushed
    exact began v _ rfl rfl pushed
  · -- no: the pull is pushed with no place, and the try begins only for a container
    simp only [free, ↓reduceIte]
    refine Ok.bind (push_appends _ _) ?_; intro v pushed
    cases containers
    · -- `else { out.push(Record(pull, Queued)) }`: it waits for a place
      simp only [Bool.false_eq_true, ↓reduceIte]
      exact recorded v _ rfl rfl pushed
    · simp only [↓reduceIte]
      exact began v _ rfl rfl pushed

/-- The loop of `cancel` over the other pulls that lack a layer of the cancelled one is
`KeepsStopping`
when none of the names it goes over is `p`: it calls `let_go` and `begin_try` for each. -/
theorem cancel_loop_keeps_stopping (p : Std.U32) (iter : alloc.vec.into_iter.IntoIter Std.U32)
    (c : Core) (out : alloc.vec.Vec Action) (distinct_c : distinct c) (stopping : Stopping p c)
    (not_p : ∀ x ∈ iter.val, x ≠ p) : Ok (cancel_loop iter c out) (KeepsStopping p c out) := by
  unfold cancel_loop
  refine Ok.loop (I := fun x => (∀ y ∈ x.1.val, y ≠ p) ∧ KeepsStopping p c out (x.2.1, x.2.2)) ?_
    ⟨not_p, KeepsStopping.refl _ distinct_c stopping⟩
  rintro ⟨it, c1, out1⟩ ⟨not_p, so_far⟩
  dsimp only at not_p so_far
  unfold cancel_loop.body
  refine Ok.bind (into_iter_next _) ?_
  rintro ⟨o, it1⟩ (⟨rfl, _⟩ | ⟨other, rest, rfl, cons, is_rest⟩)
  · exact Ok.ok.mpr so_far
  · have other_not_p := not_p other (by rw [cons]; exact List.mem_cons_self)
    have rest_not_p : ∀ y ∈ it1.val, y ≠ p := fun y hy =>
      not_p y (by rw [cons, ← is_rest] at *; exact List.mem_cons_of_mem _ hy)
    -- the pull of that name is looked up
    refine Ok.bind (pull_at_sound c1 other) ?_
    intro o1 found
    cases o1 with
    | none => exact Ok.ok.mpr ⟨rest_not_p, so_far⟩
    | some at_ =>
      obtain ⟨in_range, named⟩ := found at_ rfl
      simp only []
      -- it lets go of its layers, then begins its try again
      refine Ok.bind ((let_go_changes_layers c1 at_ out1).and
        (let_go_keeps_stopping p c1 at_ out1 so_far.1 so_far.2.1)) ?_
      rintro ⟨c2, out2⟩ ⟨⟨_, _, _, ls, pulls2⟩, let_go_did⟩
      dsimp only at pulls2
      refine Ok.bind (begin_try_keeps_stopping p c2 at_ out2 let_go_did.1 let_go_did.2.1 ?_) ?_
      · intro h
        simpa [pulls2, alloc.vec.Vec.set, named] using other_not_p
      · rintro ⟨c3, out3⟩ began
        exact Ok.ok.mpr ⟨rest_not_p, so_far.trans (let_go_did.trans began)⟩

/-- `cancel` is `KeepsStopping`: a pull that is queued or waiting is left, a pull that runs is
marked `Cancelling` and told to stop (`Abort (Pull pull)`, a pull that is not named `p`, since it
is not being stopped), and the other pulls that lacked a layer of it, which are working so not
named `p`, let go and begin their try again. -/
theorem cancel_keeps_stopping (p : Std.U32) (c : Core) (pull : Std.U32) (out : alloc.vec.Vec Action)
    (distinct_c : distinct c) (stopping : Stopping p c) :
    Ok (cancel c pull out) (KeepsStopping p c out) := by
  unfold cancel
  -- the pull is looked up; if there is none, nothing is done
  refine Ok.bind (pull_at_sound c pull) ?_
  intro o found
  cases o with
  | none => exact Ok.ok.mpr (KeepsStopping.refl _ distinct_c stopping)
  | some at_ =>
  obtain ⟨in_range, named⟩ := found at_ rfl
  simp only []
  rw [index_in_range _ _ in_range]
  simp only [bind_ok]
  split
  · exact (leave_keeps_stopping p c at_ out distinct_c stopping)
  · rename_i step running
    -- it runs: its phase becomes `Cancelling`
    refine Ok.bind (Ok.any _) ?_; intro mine _
    rw [index_mut_in_range _ _ in_range]
    simp only [bind_ok, uncurry_eq]
    let cancelling : Pull := { c.pulls.val[at_.val] with phase := Phase.Cancelling }
    have marked := KeepsStopping.of_set (p := p)
      { c with pulls := alloc.vec.Vec.set c.pulls at_ cancelling }
      out out at_.val cancelling distinct_c stopping
      in_range rfl (fun _ => rfl) (by simp [alloc.vec.Vec.set]) [] (by simp) (by simp)
    -- it lets go of its layers
    refine Ok.bind (let_go_keeps_stopping p _ at_ out marked.1 marked.2.1) ?_
    rintro ⟨c1, out1⟩ let_go_did
    simp only [uncurry_eq]
    -- `Abort (Pull pull)`: the pull is running, so it is not named `p`
    have not_named_p : pull ≠ p := by
      intro same
      have := stopping _ (List.getElem_mem in_range) (named.trans same)
      rw [running] at this; cases this
    refine Ok.bind (push_appends _ _) ?_; intro out2 pushed_abort
    have aborted := KeepsStopping.push (c := c1) let_go_did.1 let_go_did.2.1 pushed_abort
      (not_about_single fun is_about => by simpa [about] using not_named_p is_about)
    -- the other pulls that lacked a layer of it are working, so not named `p`
    refine Ok.bind (lacking_working c1 _) ?_; intro v1 working
    refine Ok.bind (Q := fun it => it = v1) (Ok.ok.mpr rfl) ?_
    intro it hit; subst it
    refine (cancel_loop_keeps_stopping p v1 c1 out2 aborted.1 aborted.2.1 ?_).mono ?_
    · intro x hx named_p
      obtain ⟨q, hq, rfl, is_working⟩ := working x hx
      have := aborted.2.1 q hq named_p
      rw [is_working] at this; cases this
    · exact fun r looped => marked.trans (let_go_did.trans (aborted.trans looped))
  · exact (leave_keeps_stopping p c at_ out distinct_c stopping)
  · exact Ok.ok.mpr (KeepsStopping.refl _ distinct_c stopping)

/-- `succeeded` is `KeepsStopping`: it keeps the pulls but for the pull it is told of, which it ends
(`leave`) if it is being stopped, and for `progressed` of the working ones. -/
theorem succeeded_keeps_stopping (p : Std.U32) (c : Core) (work : Work) (out : alloc.vec.Vec Action)
    (distinct_c : distinct c) (stopping : Stopping p c) :
    Ok (succeeded c work out) (KeepsStopping p c out) := by
  have nothing := KeepsStopping.refl (p := p) (c := c) out distinct_c stopping
  unfold succeeded
  cases work with
  | Pull pull =>
    refine Ok.bind (pull_at_sound c pull) ?_
    intro o found
    cases o with
    | none => exact Ok.ok.mpr nothing
    | some at_ =>
      obtain ⟨in_range, named⟩ := found at_ rfl
      simp only []
      rw [index_in_range _ _ in_range]
      simp only [bind_ok]
      split
      · exact Ok.ok.mpr nothing
      · rename_i step running
        split
        · exact Ok.ok.mpr nothing
        · exact Ok.ok.mpr nothing
        · -- the driver's pull ended: the pull works again
          refine Ok.bind (index_mut_result _ _) ?_
          rintro _ ⟨in_range', rfl⟩
          simp only [uncurry_eq]
          refine Ok.bind (Ok.any _) ?_; rintro ⟨s1, back1⟩ _
          simp only [uncurry_eq]
          refine Ok.bind (Ok.any _) ?_; rintro ⟨iter, back2⟩ _
          simp only [uncurry_eq]
          refine Ok.bind (Ok.any _) ?_; intro back _
          refine Ok.ok.mpr (KeepsStopping.of_set _ out out at_.val
            { c.pulls.val[at_.val] with phase := Phase.Running Step.Working, progressed := true }
            distinct_c stopping in_range rfl ?_ (by simp [alloc.vec.Vec.set]) []
            (by simp) (by simp))
          intro named_p
          have := stopping _ (List.getElem_mem in_range) named_p
          rw [running] at this; cases this
        · exact leave_keeps_stopping p c at_ out distinct_c stopping
      · exact Ok.ok.mpr nothing
      · exact leave_keeps_stopping p c at_ out distinct_c stopping
  | Layer layer =>
    refine Ok.bind (Ok.any _) ?_; intro o _
    cases o with
    | none => exact Ok.ok.mpr nothing
    | some l =>
      simp only []
      refine Ok.bind (Ok.any _) ?_; intro l1 _
      refine Ok.bind (Ok.any _) ?_; intro committing _
      split
      · -- the commit of the layer ended: the layer is stored, the pulls that lack it progress
        refine Ok.bind (Ok.any _) ?_; rintro ⟨l2, back⟩ _
        simp only [uncurry_eq]
        refine Ok.bind (Ok.any _) ?_; intro one _
        refine Ok.bind (progress_keeps_pulls _ _) ?_; rintro c1 ⟨kept, -⟩
        exact Ok.ok.mpr (KeepsStopping.of_kept c1 out out [] distinct_c stopping kept
          (by simp) (by simp))
      · exact Ok.ok.mpr nothing
  | Group group =>
    refine Ok.bind (Ok.any _) ?_; intro o _
    cases o with
    | none => exact Ok.ok.mpr nothing
    | some g =>
      simp only []
      refine Ok.bind (Ok.any _) ?_; intro g1 _
      split
      · exact Ok.ok.mpr nothing
      · -- the fetch of the group ended: the pulls that lack its layers progress
        refine Ok.bind (Ok.any _) ?_; rintro ⟨g2, back⟩ _
        simp only [uncurry_eq]
        refine Ok.bind (Ok.any _) ?_; intro g3 _
        refine Ok.bind (Ok.any _) ?_; intro needed_by _
        refine Ok.bind (progress_keeps_pulls _ _) ?_; rintro c1 ⟨kept, -⟩
        exact Ok.ok.mpr (KeepsStopping.of_kept c1 out out [] distinct_c stopping kept
          (by simp) (by simp))
      · exact Ok.ok.mpr nothing

/-- The loop of `failed` over the pulls whose try fails (`try_failed` for each) is `KeepsStopping`
when
none of the names it goes over is `p`. -/
theorem failed_loop0_keeps_stopping (p : Std.U32) (iter : alloc.vec.into_iter.IntoIter Std.U32)
    (c : Core) (now : Std.U64) (cl : Class) (out : alloc.vec.Vec Action)
    (distinct_c : distinct c) (stopping : Stopping p c) (not_p : ∀ x ∈ iter.val, x ≠ p) :
    Ok (failed_loop0 iter c now cl out) (KeepsStopping p c out) := by
  unfold failed_loop0
  refine Ok.loop (I := fun x => (∀ y ∈ x.1.val, y ≠ p) ∧ KeepsStopping p c out (x.2.1, x.2.2)) ?_
    ⟨not_p, KeepsStopping.refl _ distinct_c stopping⟩
  rintro ⟨it, c1, out1⟩ ⟨not_p, so_far⟩
  dsimp only at not_p so_far
  unfold failed_loop0.body
  refine Ok.bind (into_iter_next _) ?_
  rintro ⟨o, it1⟩ (⟨rfl, _⟩ | ⟨other, rest, rfl, cons, is_rest⟩)
  · exact Ok.ok.mpr so_far
  · have other_not_p := not_p other (by rw [cons]; exact List.mem_cons_self)
    have rest_not_p : ∀ y ∈ it1.val, y ≠ p := fun y hy =>
      not_p y (by rw [cons, ← is_rest] at *; exact List.mem_cons_of_mem _ hy)
    refine Ok.bind (pull_at_sound c1 other) ?_
    intro o1 found
    cases o1 with
    | none => exact Ok.ok.mpr ⟨rest_not_p, so_far⟩
    | some at_ =>
      obtain ⟨in_range, named⟩ := found at_ rfl
      simp only []
      refine Ok.bind (try_failed_keeps_stopping p c1 now at_ cl out1 so_far.1 so_far.2.1
        (fun _ => named ▸ other_not_p)) ?_
      rintro ⟨c2, out2⟩ failed
      exact Ok.ok.mpr ⟨rest_not_p, so_far.trans failed⟩

/-- `failed` is `KeepsStopping`: the tries it fails are those of working pulls (or of the one
running
pull it is told of), none of them named `p`, and a pull that is being stopped is ended (`leave`). -/
theorem failed_keeps_stopping (p : Std.U32) (c : Core) (now : Std.U64) (work : Work) (cl : Class)
    (out : alloc.vec.Vec Action) (distinct_c : distinct c) (stopping : Stopping p c) :
    Ok (failed c now work cl out) (KeepsStopping p c out) := by
  have nothing := KeepsStopping.refl (p := p) (c := c) out distinct_c stopping
  -- the pulls that wait for a layer or a group are working, so not named `p`
  have working_not_p : ∀ (c1 : Core) (v : alloc.vec.Vec Std.U32), c1.pulls = c.pulls →
      (∀ x ∈ v.val, ∃ q ∈ c1.pulls.val, q.id = x ∧ q.phase = Phase.Running Step.Working) →
      ∀ x ∈ v.val, x ≠ p := by
    intro c1 v same_pulls working x hx named_p
    obtain ⟨q, hq, rfl, is_working⟩ := working x hx
    have := stopping q (same_pulls ▸ hq) named_p
    rw [is_working] at this; cases this
  unfold failed
  cases work with
  | Pull pull =>
    refine Ok.bind (pull_at_sound c pull) ?_
    intro o found
    cases o with
    | none => exact Ok.ok.mpr nothing
    | some at_ =>
      obtain ⟨in_range, named⟩ := found at_ rfl
      simp only []
      rw [index_in_range _ _ in_range]
      simp only [bind_ok]
      split
      · exact Ok.ok.mpr nothing
      · rename_i step running
        -- the try of the pull fails (it is not named `p`: it runs)
        have not_p : pull ≠ p := by
          intro same
          have := stopping _ (List.getElem_mem in_range) (named.trans same)
          rw [running] at this; cases this
        have one : Ok (alloc.vec.IntoIteratorVec.into_iter
            (alloc.slice.Slice.into_vec (Std.Array.to_slice (Array.make 1#usize [pull]))))
            (fun it => it.val = [pull]) := Ok.ok.mpr rfl
        simp only [lift, bind_ok]
        refine Ok.bind one ?_; intro it is_pull
        exact failed_loop0_keeps_stopping p it c now cl out distinct_c stopping
          (by rw [is_pull]; simpa using not_p)
      · exact Ok.ok.mpr nothing
      · exact leave_keeps_stopping p c at_ out distinct_c stopping
  | Layer layer =>
    refine Ok.bind (Ok.any _) ?_; intro o _
    cases o with
    | none => exact Ok.ok.mpr nothing
    | some l =>
      simp only []
      refine Ok.bind (Ok.any _) ?_; intro l1 _
      refine Ok.bind (Ok.any _) ?_; intro b _
      split
      · exact Ok.ok.mpr nothing
      · refine Ok.bind (Ok.any _) ?_; rintro ⟨l2, back⟩ _
        simp only [uncurry_eq]
        refine Ok.bind (Ok.any _) ?_; intro s _
        refine Ok.bind (lacking_working _ _) ?_; intro failing working
        refine Ok.bind (Q := fun it => it = failing) (Ok.ok.mpr rfl) ?_
        intro it hit; subst it
        rw [failed_loops_are_the_same.1]
        exact failed_loop0_keeps_stopping p failing _ now cl out distinct_c stopping
          (working_not_p _ failing rfl working)
  | Group group =>
    refine Ok.bind (Ok.any _) ?_; intro o _
    cases o with
    | none => exact Ok.ok.mpr nothing
    | some g =>
      simp only []
      refine Ok.bind (Ok.any _) ?_; intro g1 _
      refine Ok.bind (Ok.any _) ?_; intro b _
      split
      · refine Ok.bind (Ok.any _) ?_; rintro ⟨g2, back⟩ _
        simp only [uncurry_eq]
        refine Ok.bind (Ok.any _) ?_; intro g3 _
        refine Ok.bind (lacking_working _ _) ?_; intro failing working
        refine Ok.bind (Q := fun it => it = failing) (Ok.ok.mpr rfl) ?_
        intro it hit; subst it
        rw [failed_loops_are_the_same.2]
        exact failed_loop0_keeps_stopping p failing _ now cl out distinct_c stopping
          (working_not_p _ failing rfl working)
      · exact Ok.ok.mpr nothing

/-- `prepared` is `KeepsStopping`: an answer that comes late only tells back layers and groups,
and an answer in time is for a pull at `Running Preparing`, so not named `p`: that pull gets its
layers and works. -/
theorem prepared_keeps_stopping (p : Std.U32) (c : Core) (pull : Std.U32)
    (layers : alloc.vec.Vec Std.U32)
    (groups : alloc.vec.Vec GroupFact) (out : alloc.vec.Vec Action)
    (distinct_c : distinct c) (stopping : Stopping p c) :
    Ok (prepared c pull layers groups out) (KeepsStopping p c out) := by
  unfold prepared
  -- the pull is looked up, and it is kept only if it is preparing
  refine Ok.bind (Ok.any _) ?_; intro o _
  refine Ok.bind (filter_preparing c o) ?_; intro at1 preparing
  refine Ok.bind (Ok.any _) ?_; intro fresh _
  refine Ok.bind (Ok.any _) ?_; intro fresh1 _
  cases at1 with
  | none =>
    -- a late answer: the layers and the groups it named are told back
    refine Ok.bind (Ok.any _) ?_; intro iter _
    refine Ok.bind ((prepared_loop0_kinds iter out).appends.mono fun _ h => h.noPull) ?_
    intro out1 no_pull1
    refine Ok.bind (Ok.any _) ?_; intro iter1 _
    refine Ok.bind
      ((prepared_loop1_kinds iter1 out1).appends.mono fun _ h => no_pull1.trans h.noPull) ?_
    intro out2 no_pull2
    obtain ⟨t, pushed, none_about⟩ := AppendsOnly.appended no_pull2
    exact Ok.ok.mpr (KeepsStopping.push distinct_c stopping pushed fun a ha => none_about a ha p)
  | some at2 =>
    obtain ⟨in_range, is_preparing⟩ := preparing at2 rfl
    -- an answer in time: its groups and layers are kept or told back
    refine Ok.bind (Ok.any _) ?_; intro iter _
    refine Ok.bind
      ((prepared_loop2_kinds iter c.groups out fresh1).appends.mono fun _ h => h.noPull) ?_
    rintro ⟨v, out1⟩ no_pull1
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
    obtain ⟨t, pushed, none_about⟩ := AppendsOnly.appended no_pull1
    refine Ok.ok.mpr (KeepsStopping.of_set _ out out1 at2.val
      { c.pulls.val[at2.val] with layers := layers, phase := Phase.Running Step.Working }
      distinct_c stopping in_range rfl ?_ (by simp [alloc.vec.Vec.set]) t pushed
      fun a ha => none_about a ha p)
    intro named_p
    have := stopping _ (List.getElem_mem in_range) named_p
    rw [is_preparing] at this; cases this

/-- The loop of a `Tick` over the pulls begins the try of the pulls that wait and whose time came:
they wait, so they are not stopping, so not named `p`: it is `KeepsStopping`. -/
theorem step_loop_keeps_stopping (p : Std.U32) (iter : core.ops.range.Range Std.Usize) (c : Core)
    (now : Std.U64) (out : alloc.vec.Vec Action) (distinct_c : distinct c)
    (stopping : Stopping p c) : Ok (step_loop iter c now out) (KeepsStopping p c out) := by
  unfold step_loop
  refine Ok.loop (I := fun x => KeepsStopping p c out (x.2.1, x.2.2)) ?_
    (KeepsStopping.refl _ distinct_c stopping)
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
    · rename_i t waiting
      split
      · -- the wait is over: the try begins
        refine Ok.bind (begin_try_keeps_stopping p c1 at_ out1 so_far.1 so_far.2.1 ?_) ?_
        · intro h named_p
          have := so_far.2.1 _ (List.getElem_mem in_range) named_p
          rw [waiting] at this; cases this
        · rintro ⟨c2, out2⟩ began
          exact Ok.ok.mpr (so_far.trans began)
      · exact Ok.ok.mpr so_far
    · exact Ok.ok.mpr so_far

/-- `advance` after something `KeepsStopping` is `KeepsStopping` together. -/
theorem advance_after {p : Std.U32} {c c1 : Core} {out out1 : alloc.vec.Vec Action}
    (now : Std.U64) (first : KeepsStopping p c out (c1, out1)) :
    Ok (advance c1 now out1) (KeepsStopping p c out) :=
  (advance_keeps_stopping p c1 now out1 first.1 first.2.1).mono fun _ second => first.trans second

/-- `Hurry` boosts a pull (its name and its phase are as they were): `KeepsStopping`. -/
theorem hurried_keeps_stopping (p : Std.U32) (c : Core) (out : alloc.vec.Vec Action)
    (distinct_c : distinct c) (stopping : Stopping p c) (at_ : Std.Usize)
    (in_range : at_.val < c.pulls.val.length) :
    KeepsStopping p c out (hurried c at_ in_range, out) :=
  KeepsStopping.of_set (hurried c at_ in_range) out out at_.val
    { c.pulls.val[at_.val] with boosted := true } distinct_c stopping in_range rfl
    (fun named_p => stopping (c.pulls.val[at_.val]) (List.getElem_mem in_range) named_p)
    (set_val _ _ _) [] (by simp)
    (by simp)

/-- `Hurry` of a pull that is queued or waits begins its try (it is not the pull `p`, which is being
stopped): `KeepsStopping`. -/
theorem hurried_begins_keeps_stopping (p : Std.U32) (c : Core) (out : alloc.vec.Vec Action)
    (distinct_c : distinct c) (stopping : Stopping p c) (at_ : Std.Usize)
    (in_range : at_.val < c.pulls.val.length) (idle : Idle c.pulls.val[at_.val]) :
    Ok (begin_try (hurried c at_ in_range) at_ out) (KeepsStopping p c out) := by
  have boosted := hurried_keeps_stopping p c out distinct_c stopping at_ in_range
  refine (begin_try_keeps_stopping p _ at_ out boosted.1 boosted.2.1 ?_).mono
    fun _ began => boosted.trans began
  intro _ named_p
  have stopped := stopping _ (List.getElem_mem in_range) (by simpa [hurried, set_val] using named_p)
  rcases idle with idle | ⟨t, idle⟩ <;> simp [idle] at stopped

/-- **The step of every event is `KeepsStopping`** when the core holds `p`, being stopped: each
event is a call of one function of lib.rs (then `advance`), or code of `step` itself
(`Step.lean`), and each piece is `KeepsStopping`. -/
theorem step_keeps_stopping (p : Std.U32) (c : Core) (now : Std.U64) (ev : Event)
    (out : alloc.vec.Vec Action) (distinct_c : distinct c) (stopping : Stopping p c)
    (held_p : held c p) : Ok (step c now ev out) (KeepsStopping p c out) :=
  StepFacts.holds (told := fun _ => True) (A := KeepsStopping p c out) (Q := KeepsStopping p c out)
    { advance_ok := fun r first => advance_after now first
      add_ok := fun pull containers =>
        add_keeps_stopping p c pull containers out distinct_c stopping held_p
      cancel_ok := fun pull => cancel_keeps_stopping p c pull out distinct_c stopping
      prepared_ok := fun pull layers groups _ =>
        prepared_keeps_stopping p c pull layers groups out distinct_c stopping
      succeeded_ok := fun work => succeeded_keeps_stopping p c work out distinct_c stopping
      failed_ok := fun work cl => failed_keeps_stopping p c now work cl out distinct_c stopping
      hurry_of_none := KeepsStopping.refl out distinct_c stopping
      hurry_boosts := hurried_keeps_stopping p c out distinct_c stopping
      hurry_begins := hurried_begins_keeps_stopping p c out distinct_c stopping
      -- (the record of the starts changes, not the pulls)
      start_of_a_layer := fun layer => (start_at_keeps_pulls c layer now).mono fun _ same_pulls cs =>
        KeepsStopping.of_kept _ out out [] distinct_c stopping
          (by rw [(same_pulls cs).1]; exact forall₂_self Kept.refl _) (by simp) (by simp)
      -- (a `Wake` is not about a pull)
      wake := fun _ kept _ _ pushed => kept.trans (KeepsStopping.push kept.1 kept.2.1 pushed
        (not_about_single fun named => nomatch named))
      tick_loop := fun iter => step_loop_keeps_stopping p iter c now out distinct_c stopping } ev
    trivial

/-- Names that are distinct leave one pull of each name: if the pull `q` named `p` is being
stopped, every pull named `p` is. -/
theorem stopping_of_distinct {p : Std.U32} {c : Core} (distinct_c : distinct c)
    (named : phase c p Phase.Cancelling) : Stopping p c := by
  obtain ⟨q, hq, named_p, stopped⟩ := named
  intro x hx named_x
  have same : x = q := by
    obtain ⟨i, hi, hix⟩ := List.getElem_of_mem hx
    obtain ⟨j, hj, hjq⟩ := List.getElem_of_mem hq
    have same_place := (List.Nodup.getElem_inj_iff (i := i) (j := j) distinct_c
      (hi := by simpa using hi) (hj := by simpa using hj)).mp
      (by simp [hix, hjq, named_x, named_p])
    subst same_place
    rw [← hix, ← hjq]
  rw [same]; exact stopped

/-- **A stopping pull only ends** (the statement of Spec.lean).  `step_keeps_stopping` read at
the end: what `step` asked about `p` is `End p` at most; the pull is still stopping, or it is
gone and `End p` was asked; and when `End p` was asked it is gone. -/
theorem a_stopping_pull_only_ends : AStoppingPullOnlyEnds := by
  intro c now ev out c' out' p distinct_c stopped returns
  have held_p : held c p := by obtain ⟨q, hq, named_p, _⟩ := stopped; exact ⟨q, hq, named_p⟩
  obtain ⟨_, stopping', t, pushed, only_ends, held_after, _, end_gone⟩ :=
    (step_keeps_stopping p c now ev out distinct_c (stopping_of_distinct distinct_c stopped)
      held_p).eq returns
  have asked_is : ∀ a, asked out out' a ↔ a ∈ t := by
    intro a; simp [asked, pushed]
  refine ⟨fun a is_asked about_p => only_ends a ((asked_is a).mp is_asked) about_p, ?_,
    fun end_asked => end_gone ((asked_is _).mp end_asked)⟩
  by_cases held_p' : held c' p
  · obtain ⟨q, hq, named_p⟩ := held_p'
    exact Or.inl ⟨q, hq, named_p, stopping' q hq named_p⟩
  · exact Or.inr ⟨held_p', (asked_is _).mpr ((held_after held_p).resolve_left held_p')⟩

/-- `Ended p out r`: the step asked for `End p` (among what it appended to `out`) and the core
holds no pull named `p`. -/
def Ended (p : Std.U32) (out : alloc.vec.Vec Action) (r : Core × alloc.vec.Vec Action) : Prop :=
  (∃ t, r.2.val = out.val ++ t ∧ Action.End p ∈ t) ∧ ¬ held r.1 p

/-- `leave` of the pull at `at_`, named `p`, asks for `End p` and the core holds `p` no more
(the names are distinct, so no other pull is named `p`). -/
theorem leave_ends (p : Std.U32) (c : Core) (at_ : Std.Usize) (out : alloc.vec.Vec Action)
    (distinct_c : distinct c) (in_range : at_.val < c.pulls.val.length)
    (named : (c.pulls.val[at_.val]).id = p) : Ok (leave c at_ out) (Ended p out) := by
  refine (leave_removes_the_pull c at_ out).mono ?_
  rintro r ⟨_, t, ⟨rest, pushed⟩, names⟩
  refine ⟨⟨t ++ [Action.End p] ++ rest, by rw [← pushed]; simp [named], by simp⟩, ?_⟩
  rintro held_after
  have in_names := held_iff_name.mp held_after
  rw [names] at in_names
  exact name_not_in_others _ distinct_c at_.val in_range (named ▸ in_names)

/-- When the names are distinct, `pull_at` finds the pull named `p` that is being stopped, at a
place whose pull is at `Cancelling`. -/
theorem stopped_pull_found (p : Std.U32) (c : Core) (distinct_c : distinct c)
    (stopped : phase c p Phase.Cancelling) :
    Ok (Core.pull_at c p) (fun o => ∃ n : Std.Usize, o = some n ∧
      ∃ h : n.val < c.pulls.val.length, (c.pulls.val[n.val]).id = p ∧
        (c.pulls.val[n.val]).phase = Phase.Cancelling) := by
  obtain ⟨q, hq, named_p, stop⟩ := stopped
  obtain ⟨j, hj, rfl⟩ := List.getElem_of_mem hq
  refine (pull_at_unique c p distinct_c j hj named_p).mono ?_
  rintro o ⟨n, rfl, rfl⟩
  exact ⟨n, rfl, hj, named_p, stop⟩

/-- `succeeded` for the pull `p` that is being stopped ends it. -/
theorem succeeded_ends_the_stop (p : Std.U32) (c : Core) (out : alloc.vec.Vec Action)
    (distinct_c : distinct c) (stopped : phase c p Phase.Cancelling) :
    Ok (succeeded c (Work.Pull p) out) (Ended p out) := by
  unfold succeeded
  refine Ok.bind (stopped_pull_found p c distinct_c stopped) ?_
  rintro o ⟨n, rfl, in_range, named, is_stopped⟩
  simp only []
  rw [index_in_range _ _ in_range]
  simp only [bind_ok, is_stopped]
  exact leave_ends p c n out distinct_c in_range named

/-- `failed` for the pull `p` that is being stopped ends it, whatever the class. -/
theorem failed_ends_the_stop (p : Std.U32) (c : Core) (now : Std.U64) (cl : Class)
    (out : alloc.vec.Vec Action) (distinct_c : distinct c) (stopped : phase c p Phase.Cancelling) :
    Ok (failed c now (Work.Pull p) cl out) (Ended p out) := by
  unfold failed
  refine Ok.bind (stopped_pull_found p c distinct_c stopped) ?_
  rintro o ⟨n, rfl, in_range, named, is_stopped⟩
  simp only []
  rw [index_in_range _ _ in_range]
  simp only [bind_ok, is_stopped]
  exact leave_ends p c n out distinct_c in_range named

/-- **The end of the stop ends the pull** (the statement of Spec.lean): `step` on
`Done (Pull p) r` is `succeeded` or `failed`, which end the pull (`leave`), then `advance`, which
asks more and keeps the names. -/
theorem the_end_of_the_stop_ends_it : TheEndOfTheStopEndsIt := by
  intro c now r out c' out' p distinct_c stopped returns
  have ended : Ok (step c now (Event.Done (Work.Pull p) r) out) (Ended p out) := by
    unfold step
    simp only []
    -- `succeeded` or `failed` of the pull ends it
    refine Ok.bind (Q := Ended p out) ?_ ?_
    · cases r with
      | Ok _ => exact succeeded_ends_the_stop p c out distinct_c stopped
      | Err cl => exact failed_ends_the_stop p c now cl out distinct_c stopped
    -- `advance` pushes more, and keeps the names
    rintro ⟨c1, out1⟩ ⟨⟨t, pushed, end_in⟩, gone⟩
    refine (advance_keeps_pulls c1 now out1).mono ?_
    rintro r' ⟨⟨t', pushed', _⟩, kept, _⟩
    refine ⟨⟨t ++ t', by rw [pushed', pushed, List.append_assoc],
      List.mem_append_left _ end_in⟩, ?_⟩
    intro held_after
    exact gone (held_iff_name.mpr ((kept_names kept) ▸ held_iff_name.mp held_after))
  obtain ⟨⟨t, pushed, end_in⟩, gone⟩ := ended.eq returns
  exact ⟨by simp [asked, pushed, end_in], gone⟩

end LazyCore
