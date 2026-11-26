-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: one step of the loop keeps `Inv`, and the answer of the core obeys the
-- rules of rules.rs (`RulesA`), for each of the four events.
--
-- Why it is needed: it is the induction step of Reach.lean: the claims of Spec.lean hold in every
-- reachable state because they hold after each step from a state that satisfies `Inv`.
--
-- Read before this file: Decision.lean.
import GroupCore.Decision
namespace GroupCore

/-- The loop reports that a request ended or a chunk came. -/
def EvA.reports : EvA → Prop
  | .chunk _ => True
  | .ended .. => True
  | _ => False

/-- The rules of rules.rs for the answer `act` to the event `ev` in the state `s` (the numbers are
those the loop knows once it has the event, `s.pre ev`). -/
structure RulesA (s : AS) (ev : EvA) (act : Act) (a : AG) : Prop where
  search_once : act = .search → (s.pre ev).searching = false
  search_room : act = .search → 0 < (s.pre ev).room
  search_beside : act = .search → (s.pre ev).running ≠ [] → ev = .hedgeDue
  ask_found : ∀ q, act = .ask q → q < (s.pre ev).found
  ask_free : ∀ q, act = .ask q → q ∉ (s.pre ev).running
  ask_beside : ∀ q, act = .ask q → (s.pre ev).running ≠ [] →
    ev = .hedgeDue ∨ ((∃ n, ev = .found n) ∧ (s.pre ev).hedged = true)
  ask_again : ∀ q, act = .ask q → 0 < (s.pre ev).asked q →
    (s.pre ev).noRoom q = true ∧ (s.pre ev).noRoomAt q < (s.pre ev).passed
  ask_times : ∀ q, act = .ask q → (s.pre ev).asked q + 1 ≤ (s.pre ev).items + 1
  ask_unpassed : ∀ q, act = .ask q → (s.pre ev).passed < (s.pre ev).items
  finish_when : act = .finish → (s.pre ev).passed = (s.pre ev).items ∨
    ((s.pre ev).running = [] ∧ (s.pre ev).searching = false ∧ (s.pre ev).room = 0 ∧
      ∀ q, q < (s.pre ev).found → 0 < (s.pre ev).asked q ∧
        ((s.pre ev).noRoom q = false ∨ (s.pre ev).passed ≤ (s.pre ev).noRoomAny))
  all_passed : ev.reports → (s.pre ev).passed = (s.pre ev).items → act = .finish
  live : act ≠ .finish → (s.pre ev).passed < (s.pre ev).items
  never_idle : act ≠ .finish →
    (s.after ev act a).running ≠ [] ∨ (s.after ev act a).searching = true
  hedge_acts : ev = .hedgeDue → act = .search ∨ ∃ q, act = .ask q

/-- When `go` decides after the event, the answer obeys the rules and `Inv` is kept. -/
theorem go_rules (s : AS) (ev : EvA) (act : Act) (a : AG) (hi : Inv (s.pre ev))
    (not_hedge : ev ≠ .hedgeDue) (h : goA (s.pre ev).g = (act, a)) :
    Inv (s.after ev act a) ∧ RulesA s ev act a := by
  obtain ⟨inv, search, ask, finish, all, idle, below⟩ := go_ok (s.pre ev) ev act a hi h
  refine ⟨inv, ?_⟩
  constructor
  · exact fun e => (search e).1
  · exact fun e => (search e).2.1
  · exact fun e r => absurd (search e).2.2 r
  · exact fun q e => (ask q e).1
  · exact fun q e => (ask q e).2.1
  · exact fun q e r => absurd (ask q e).2.2.1 r
  · exact fun q e => (ask q e).2.2.2.1
  · intro q e
    have := (ask q e).2.2.2.2.1
    have le := hi.passed_le
    omega
  · exact fun q e => by have := (ask q e).2.2.2.2.2; have := hi.passed_le; omega
  · exact finish
  · exact fun _ e => all e
  · exact fun e => lt_of_le_of_ne hi.passed_le (below e)
  · exact idle
  · exact fun e => absurd e not_hedge

/-- One step of the loop keeps `Inv`, and the answer of the core obeys the rules. -/
theorem step_ok (s : AS) (ev : EvA) (hi : Inv s) (below : s.passed < s.items)
    (en : EnabledA s ev) :
    Inv (s.after ev (s.answer ev).1 (s.answer ev).2) ∧ RulesA s ev (s.answer ev).1 (s.answer ev).2 := by
  rcases hans : s.answer ev with ⟨act, a⟩
  show Inv (s.after ev act a) ∧ RulesA s ev act a
  -- a chunk or the end of a request: `go` decides; the end of a search: the first peer found is
  -- asked at once if the hedge timer started the search and a request runs, else `go` decides;
  -- the hedge timer: ask the next peer, or search
  cases ev with
  | chunk p =>
    exact go_rules s _ act a (chunk_inv s hi p en) (by simp) hans
  | ended q nr p =>
    exact go_rules s _ act a (ended_inv s hi q nr p en) (by simp) hans
  | found n =>
    have hp := found_inv s hi n en
    simp only [AS.answer] at hans
    split at hans
    · rename_i c
      obtain ⟨q, rest, hq, hact, hfound, hfree, hagain, htimes, hsearch, hinv⟩ :=
        ask_first_ok (s.pre (.found n)) (.found n) hp c.2
      have e1 : act = (askFirstA (s.pre (.found n)).g).1 := by rw [hans]
      have e2 : a = (askFirstA (s.pre (.found n)).g).2 := by rw [hans]
      have under_way : s.running ≠ [] := by rw [← hi.running_eq]; exact c.1
      have hedged : s.hedged = true := hi.search_hedge en.1 under_way
      have asks : act = .ask q := e1.trans hact
      subst e2 asks
      rw [hact] at hinv
      refine ⟨hinv, ?_⟩
      constructor
      · intro e; simp at e
      · intro e; simp at e
      · intro e; simp at e
      · intro q' e; simp at e; subst e; exact hfound
      · intro q' e; simp at e; subst e; exact hfree
      · intro q' e _; simp at e; subst e; exact Or.inr ⟨⟨n, rfl⟩, hedged⟩
      · intro q' e; simp at e; subst e; exact hagain
      · intro q' e; simp at e; subst e
        have : (s.pre (.found n)).passed ≤ (s.pre (.found n)).items := hp.passed_le
        omega
      · intro q' e; simp at e; subst e; exact below
      · intro e; simp at e
      · intro r; exact absurd r (by simp [EvA.reports])
      · intro _; exact below
      · intro _; left; simp [AS.after, AS.post]
      · intro e; simp at e
    · exact go_rules s _ act a hp (by simp) hans
  | hedgeDue =>
    simp only [AS.answer] at hans
    obtain ⟨armed_busy, armed_idle, armed_more⟩ := en
    have under_way : s.running ≠ [] := by rw [← hi.running_eq]; exact armed_busy
    have not_searching : s.searching = false := by rw [← hi.searching_eq]; exact armed_idle
    unfold hedgeDueA at hans
    by_cases queued : s.g.next ≠ []
    · simp only [queued, ↓reduceIte, ne_eq, not_false_eq_true] at hans
      obtain ⟨q, rest, hq, hact, hfound, hfree, hagain, htimes, hsearch, hinv⟩ :=
        ask_first_ok s .hedgeDue hi queued
      have e1 : act = (askFirstA s.g).1 := by rw [hans]
      have e2 : a = (askFirstA s.g).2 := by rw [hans]
      have asks : act = .ask q := e1.trans hact
      subst e2 asks
      rw [hact] at hinv
      refine ⟨hinv, ?_⟩
      constructor
      · intro e; simp at e
      · intro e; simp at e
      · intro e; simp at e
      · intro q' e; simp at e; subst e; exact hfound
      · intro q' e; simp at e; subst e; exact hfree
      · intro q' e _; simp at e; subst e; exact Or.inl rfl
      · intro q' e; simp at e; subst e; exact hagain
      · intro q' e; simp at e; subst e
        have : s.passed ≤ s.items := hi.passed_le
        have : s.asked q + 1 ≤ s.passed + 1 := htimes
        show s.asked q + 1 ≤ s.items + 1
        omega
      · intro q' e; simp at e; subst e; exact below
      · intro e; simp at e
      · intro r; exact absurd r (by simp [EvA.reports])
      · intro _; exact below
      · intro _; left; simp [AS.after, AS.post, AS.pre]
      · intro _; right; exact ⟨q, rfl⟩
    · have empty : s.g.next = [] := by simpa using queued
      have may : s.g.mayFind = true := by
        rcases armed_more with h | h
        · exact absurd h queued
        · exact h
      simp only [queued, may, ↓reduceIte] at hans
      obtain ⟨rfl, rfl⟩ := Prod.mk.inj hans.symm
      simp only [AG.mayFind, Bool.and_eq_true, Bool.not_eq_true', decide_eq_true_eq] at may
      obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18, h19,
        h20, h21, h22, h23, h24, h25, h26, h27, h28, h29⟩ := hi
      refine ⟨?_, ?_⟩
      · simp only [AS.after, AS.pre, AS.post]; constructor <;> grind
      constructor
      · intro _; exact not_searching
      · intro _; simp only [AS.pre, AS.room]; grind
      · intro _ _; rfl
      · intro q' e; simp at e
      · intro q' e; simp at e
      · intro q' e _; simp at e
      · intro q' e; simp at e
      · intro q' e; simp at e
      · intro q' e; simp at e
      · intro e; simp at e
      · intro r; exact absurd r (by simp [EvA.reports])
      · intro _; exact below
      · intro _; right; simp [AS.after, AS.post, AS.pre]
      · intro _; left; rfl

end GroupCore
