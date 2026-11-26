-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: every state a group can reach, until it is finished, satisfies `Inv` and
-- has items left to pass on; and every step the loop makes there obeys the rules of rules.rs.
--
-- Why it is needed: it is the induction over the steps the walk of crates/group-core/src/walk.rs
-- takes, here for every number of items and peers.
--
-- Read before this file: Step.lean.
import GroupCore.Step
namespace GroupCore

/-- A state that is not finished after a step comes of an answer other than "finish". -/
theorem not_finished_after (s : AS) (ev : EvA) (act : Act) (a : AG)
    (h : (s.after ev act a).finished = false) : act ≠ .finish := by
  intro e; subst e; simp [AS.after, AS.post] at h

/-- The numbers of items are not changed by the answer. -/
theorem passed_after (s : AS) (ev : EvA) (act : Act) (a : AG) :
    (s.after ev act a).passed = (s.pre ev).passed ∧ (s.after ev act a).items = (s.pre ev).items := by
  cases act <;> simp [AS.after, AS.post]

/-- Every state reached and not finished satisfies `Inv` and has items left. -/
theorem reach_inv {s : AS} (h : ReachA s) : s.finished = false → Inv s ∧ s.passed < s.items := by
  induction h with
  | start items passed max below => intro _; exact ⟨start_inv items passed max below, below⟩
  | step s ev _ fresh en ih =>
    intro done
    obtain ⟨hi, below⟩ := ih fresh
    obtain ⟨inv, rules⟩ := step_ok s ev hi below en
    have live := rules.live (not_finished_after s ev _ _ done)
    exact ⟨inv, by rw [(passed_after s ev _ _).1, (passed_after s ev _ _).2]; exact live⟩

end GroupCore
