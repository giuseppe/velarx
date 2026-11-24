-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proof of `ACancelIsNeverLost` (Spec.lean).
-- A pull that the core holds and that is not being stopped is, on the
-- event `Cancel p`, either ended (`End p`) or told to stop (`Abort (Pull p)`).
-- Nobody drops the request.
--
-- The argument follows the Rust, `step` then `cancel` then `advance`:
--   1. `cancel` looks the pull up (`pull_at`).  It is found, since the
--      core holds it.
--   2. If the pull is queued or waiting, `cancel` calls `leave`, which
--      pushes `End p`.  If it runs, `cancel` calls `let_go`, then pushes
--      `Abort (Pull p)`, then goes on with the other pulls (a loop that
--      only pushes).  A pull that is being stopped already is the case
--      the statement leaves out.
--   3. `step` then calls `advance`, which only pushes (Grows.lean): the
--      action is still in `out`.
--
-- Read before this file: Ok.lean, Grows.lean, Pulls.lean (it gives what
-- `leave` and `let_go` do), and the statement in Spec.lean.
--
-- Notation: `∃ t, (out.val ++ t) <+: r.2.val` is "the actions in `out` are
-- followed by some actions `t`, and these are the beginning of what the
-- function leaves" (`++` joins two lists; `<+:` is "is the beginning of";
-- `r.2` is the second part of the result, the new `out`).  `A ∈ t` is
-- "A is in `t`".
import LazyCore.Pulls

open Aeneas Aeneas.Std Result velarx_lazy_core

namespace LazyCore

attribute [local irreducible] let_go leave_loop cancel_loop advance Core.lacking

/-- `cancel` of a pull that the core holds and that is not being stopped already pushes
`End p` or `Abort (Pull p)` to `out`. -/
theorem cancel_acts (c : Core) (p : Std.U32) (out : alloc.vec.Vec Action)
    (held : ∃ q ∈ c.pulls.val, q.id = p)
    (not_cancelling : ∀ q ∈ c.pulls.val, q.id = p → q.phase ≠ Phase.Cancelling) :
    Ok (cancel c p out) (fun r => ∃ t, (out.val ++ t) <+: r.2.val ∧
      (Action.End p ∈ t ∨ Action.Abort (Work.Pull p) ∈ t)) := by
  -- the pull is found, and `leave` of it ends it, with `End p` among what it pushes
  have found_and_left : Ok (Core.pull_at c p) (fun o => ∃ n, o = some n ∧
      ∃ hn : n.val < c.pulls.val.length, (c.pulls.val[n.val]).id = p ∧
      Ok (leave c n out) (fun r => ∃ t, (out.val ++ t) <+: r.2.val ∧
        (Action.End p ∈ t ∨ Action.Abort (Work.Pull p) ∈ t))) := by
    refine ((pull_at_none c p).and (pull_at_sound c p)).mono ?_
    rintro (_ | n) ⟨not_found, named⟩
    · exact absurd held (not_found rfl)
    obtain ⟨in_range, named_p⟩ := named n rfl
    refine ⟨n, rfl, in_range, named_p, (leave_removes_the_pull c n out).mono ?_⟩
    rintro r ⟨_, t, pushed, _⟩
    exact ⟨t ++ [Action.End p], by simpa [named_p] using pushed, Or.inl (by simp)⟩
  unfold cancel
  refine Ok.bind found_and_left ?_
  rintro o ⟨n, rfl, in_range, named_p, left⟩
  simp only []
  -- the phase of the pull is read: `match c.pulls[at].phase`
  rw [index_in_range _ _ in_range]
  simp only [bind_ok]
  have not_stopping := not_cancelling _ (List.getElem_mem in_range) named_p
  split
  · -- queued: `leave`
    exact left
  · -- running: it is marked cancelling, `let_go` runs, `Abort (Pull p)` is pushed
    refine Ok.bind (Ok.any _) ?_; intro _ _
    rw [index_mut_in_range _ _ in_range]
    simp only [bind_ok, uncurry_eq]
    refine Ok.bind (let_go_changes_layers _ _ _) ?_
    rintro ⟨c1, out1⟩ ⟨⟨⟨t, pushed_by_let_go⟩, _⟩, _⟩
    dsimp only at pushed_by_let_go
    simp only [uncurry_eq]
    refine Ok.bind (push_appends _ _) ?_
    intro out2 pushed_abort
    refine Ok.bind (Ok.any _) ?_; intro _ _
    refine Ok.bind (Ok.any _) ?_; intro _ _
    -- the loop over the other pulls only pushes
    refine ((cancel_loop_kinds _ _ _).appends.mono fun _ h => h.grows).mono ?_
    intro r grown
    refine ⟨t ++ [Action.Abort (Work.Pull p)], ?_, Or.inr (by simp)⟩
    simpa [pushed_abort, ← pushed_by_let_go] using grown
  · -- waiting: `leave`
    exact left
  · -- already cancelling: excluded by the hypothesis
    exact absurd (by assumption) not_stopping

/-- **A cancel is never lost** (the statement of Spec.lean).  `step` on `Cancel p` is
`cancel` followed by `advance`: `cancel` leaves `End p` or `Abort (Pull p)` in `out`,
and `advance` only pushes, so it is still there. -/
theorem a_cancel_is_never_lost : ACancelIsNeverLost := by
  intro c now p out c' out' held not_stopping returns
  have asks_end_or_abort : Ok (step c now (Event.Cancel p) out)
      (fun r => ∃ t, (out.val ++ t) <+: r.2.val ∧
        (Action.End p ∈ t ∨ Action.Abort (Work.Pull p) ∈ t)) := by
    unfold step
    -- `cancel`
    refine Ok.bind (cancel_acts c p out held
      fun q hq hqp phase => not_stopping ⟨q, hq, hqp, phase⟩) ?_
    rintro ⟨c1, out1⟩ ⟨t, pushed, asked_by_cancel⟩
    simp only [uncurry_eq]
    -- `advance` keeps what `cancel` pushed
    exact ((advance_kinds c1 now out1).appends.mono fun _ h => pushed.trans h.grows).mono
      fun r grown => ⟨t, grown, asked_by_cancel⟩
  obtain ⟨t, pushed, asked_by_cancel⟩ := asks_end_or_abort.eq returns
  exact asked_by_cancel.imp (asked_if_appended pushed) (asked_if_appended pushed)

end LazyCore
