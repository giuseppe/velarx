-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the loop of Spec.lean (which holds the core's `Group`) and the copy the
-- proofs work on (Machine.lean, which holds the group as lists) go together: the core returns on
-- every call the loop may make, what it answers is what the model answers, and what the loop knows
-- afterwards is what the copy knows afterwards.
--
-- Why it is needed: the claims of Spec.lean are about the Rust functions; Reach.lean proves the
-- rules for the copy; this file moves each from the copy to the Rust.
--
-- Read before this file: Spec.lean, Bridge.lean and Reach.lean.
import GroupCore.Reach
import GroupCore.Bridge
import GroupCore.Spec
open Aeneas Aeneas.Std Aeneas.Data.Coinductive Result velarx_group_core
namespace GroupCore

/-- The event, as the copy has it. -/
def Event.abs : Event → EvA
  | .chunk p => .chunk p.val
  | .ended q nr p => .ended q.val nr p.val
  | .found n => .found n.val
  | .hedgeDue => .hedgeDue

/-- The loop, as the copy has it. -/
def Loop.abs (s : Loop) : AS where
  g := s.group.abs
  items := s.items
  max := s.max
  running := s.running
  searching := s.searching
  hedged := s.hedged
  exhausted := s.exhausted
  passed := s.passed
  found := s.found
  asked := s.asked
  noRoomAt := s.noRoomAt
  noRoom := s.noRoom
  noRoomAny := s.noRoomAny
  finished := s.finished

/-- A list of distinct numbers below `n` has at most `n` of them. -/
theorem nodup_length_le {l : List Nat} {n : Nat} (nodup : l.Nodup) (below : ∀ x ∈ l, x < n) :
    l.length ≤ n := by
  have := (List.subperm_of_subset nodup (fun x hx => List.mem_range.mpr (below x hx))).length_le
  simpa using this

/-- In a state that satisfies `Inv`, the requests under way and the queue together, and the requests
under way and the peers with no room together, are no more than the peers found. -/
theorem lengths_le {s : AS} (hi : Inv s) :
    s.g.underWay.length + s.g.next.length ≤ s.found ∧
    s.g.busy.length + s.g.underWay.length ≤ s.found := by
  constructor
  · have nodup : (s.running ++ s.g.next).Nodup := by
      rw [List.nodup_append]
      exact ⟨hi.running_nodup, hi.next_nodup, fun a ha b hb e => hi.next_running b hb (e ▸ ha)⟩
    have := nodup_length_le nodup (by
      intro x hx; rcases List.mem_append.mp hx with h | h
      · exact hi.running_below x h
      · exact hi.next_below x h)
    rw [hi.running_eq]; simpa using this
  · have nodup : (s.g.busy ++ s.running).Nodup := by
      rw [List.nodup_append]
      exact ⟨hi.busy_nodup, hi.running_nodup, fun a ha b hb e => hi.running_busy b hb (e ▸ ha)⟩
    have := nodup_length_le nodup (by
      intro x hx; rcases List.mem_append.mp hx with h | h
      · exact hi.busy_below x h
      · exact hi.running_below x h)
    rw [hi.running_eq]; simpa using this

/-- A Rust function that returns on every input of a kind, and whose answer satisfies `P`, returns a
result that does. -/
theorem returns_with {α : Type} {m : Result α} {P : α → Prop} (h : m ⦃ r => P r ⦄) :
    ∃ x, m = ok x ∧ P x := by
  cases m with
  | ret x => exact ⟨x, rfl, (WP.spec_ok x).mp h⟩
  | vis e k => exact ((WP.spec_vis e k).mp h).elim
  | div => exact (WP.spec_div.mp h).elim

/-- In a state that satisfies `Inv`, the call of the loop returns, and the core's answer and group
are those of the copy. -/
theorem call_returns (s : Loop) (ev : Event) (hi : Inv s.abs) (en : s.Enabled ev) :
    ∃ todo g, s.call ev = ok (todo, g) ∧ (todo.act, g.abs) = s.abs.answer ev.abs := by
  obtain ⟨wf, busy_room⟩ := lengths_le hi
  have found_le := hi.found_le
  have e_found : s.abs.found = s.found := rfl
  have e_max : s.abs.max = s.max := rfl
  have max_fits : s.max ≤ Std.Usize.max := by
    have hm : s.group.max.val = s.max := hi.max_eq
    scalar_tac
  cases ev with
  | chunk p =>
    obtain ⟨r, hr, post⟩ := returns_with (chunk_spec s.group p)
    exact ⟨r.1, r.2, hr, post⟩
  | ended q nr p =>
    have inq : q.val ∈ s.running := en.1
    have busy_len : s.group.busy.length = s.abs.g.busy.length := by
      simp [Loop.abs, Group.abs, alloc.vec.Vec.length]
    have under_len : 0 < s.abs.g.underWay.length := by
      rw [hi.running_eq]; exact List.length_pos_of_mem inq
    have : s.group.busy.length < Std.Usize.max := by
      omega
    obtain ⟨r, hr, post⟩ := returns_with (ended_spec s.group q nr p this)
    exact ⟨r.1, r.2, hr, post⟩
  | found n =>
    have enough : n.val ≤ s.room := en.2
    have fits : s.group.found.val + n.val ≤ Std.Usize.max := by
      have hf : s.group.found.val = s.found := hi.found_eq
      unfold Loop.room at enough
      split at enough <;> omega
    have under_len : s.group.under_way.length + s.group.next.length = s.abs.g.underWay.length + s.abs.g.next.length := by
      simp [Loop.abs, Group.abs, alloc.vec.Vec.length]
    have : s.group.under_way.length + s.group.next.length + n.val ≤ Std.Usize.max := by
      have hf : s.group.found.val = s.found := hi.found_eq
      unfold Loop.room at enough
      split at enough <;> omega
    obtain ⟨r, hr, post⟩ := returns_with (found_spec s.group n fits this)
    exact ⟨r.1, r.2, hr, post⟩
  | hedgeDue =>
    have under_len : s.group.under_way.length + s.group.next.length = s.abs.g.underWay.length + s.abs.g.next.length := by
      simp [Loop.abs, Group.abs, alloc.vec.Vec.length]
    have : Wf s.group := by
      unfold Wf
      omega
    obtain ⟨r, hr, post⟩ := returns_with (hedge_due_spec s.group this)
    exact ⟨r.1, r.2, hr, post⟩

/-- What the loop knows once it has the event is what the copy knows, but for the group. -/
theorem pre_abs (s : Loop) (ev : Event) :
    (s.pre ev).abs = { s.abs.pre ev.abs with g := s.abs.g } := by
  cases ev <;> simp [Loop.pre, AS.pre, Loop.abs, Event.abs]

/-- What the loop knows after the answer is what the copy knows. -/
theorem after_abs (s : Loop) (ev : Event) (todo : Do) (g : Group) :
    (s.after ev todo g).abs = s.abs.after ev.abs todo.act g.abs := by
  cases ev <;> cases todo <;> simp [Loop.after, AS.after, AS.post, AS.pre, Loop.pre, Loop.abs,
    Event.abs, Do.act]

/-- A call the loop may make, the copy may make. -/
theorem enabled_abs (s : Loop) (ev : Event) (en : s.Enabled ev) : EnabledA s.abs ev.abs := by
  cases ev with
  | chunk p => exact en
  | ended q nr p => exact en
  | found n => exact en
  | hedgeDue =>
    obtain ⟨x, hx⟩ := en
    obtain ⟨r, hr, post⟩ := returns_with (hedge_spec s.group)
    rw [hx] at hr
    simp only [ok.injEq] at hr
    subst hr
    exact post.1.mp (by simp)

/-- The group `new` makes is the start of the copy. -/
theorem start_abs (items passed max : Std.Usize) (g : Group)
    (new : Group.new items passed max = ok (g, Do.Search)) :
    (Loop.start g).abs = AS.start items.val passed.val max.val := by
  unfold Group.new at new
  simp only [ok.injEq, Prod.mk.injEq] at new
  obtain ⟨rfl, _⟩ := new
  simp [Loop.start, Loop.abs, AS.start, Group.abs, alloc.vec.Vec.new]

/-- Every state the loop reaches, the copy reaches. -/
theorem reach_abs {s : Loop} (h : Reach s) : ReachA s.abs := by
  induction h with
  | start items passed max g below new =>
    rw [start_abs items passed max g new]
    exact ReachA.start _ _ _ below
  | step s ev todo g _ fresh en call ih =>
    have hi := (reach_inv ih (by simpa [Loop.abs] using fresh)).1
    obtain ⟨todo', g', call', hans⟩ := call_returns s ev hi en
    rw [call] at call'
    simp only [ok.injEq, Prod.mk.injEq] at call'
    obtain ⟨rfl, rfl⟩ := call'
    rw [after_abs]
    have := ReachA.step s.abs ev.abs ih (by simpa [Loop.abs] using fresh) (enabled_abs s ev en)
    rw [← hans] at this
    exact this

end GroupCore
