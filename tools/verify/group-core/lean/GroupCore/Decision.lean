-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what each decision of the core does to `Inv`, and which rules of rules.rs
-- its answer obeys: asking the first of the queue, giving the peers with no room back to the queue,
-- and `go` as a whole.
--
-- Why it is needed: the rules are statements about the answer of the core in a reachable state;
-- each is read off the branch of the code that gives that answer.
--
-- Read before this file: Invariant.lean.
import GroupCore.Invariant
namespace GroupCore

/-- Asking the first of the queue: the peer is found, has no request, was never asked or said "no
room" and saw items come in since; it joins the requests under way, and `Inv` holds. -/
theorem ask_first_ok (p : AS) (ev : EvA) (hi : Inv p) (queued : p.g.next ≠ []) :
    ∃ q rest, p.g.next = q :: rest ∧ (askFirstA p.g).1 = .ask q ∧ q < p.found ∧ q ∉ p.running ∧
      (0 < p.asked q → p.noRoom q = true ∧ p.noRoomAt q < p.passed) ∧
      p.asked q + 1 ≤ p.passed + 1 ∧ p.searching = false ∧
      Inv (p.post ev (askFirstA p.g).1 (askFirstA p.g).2) := by
  obtain ⟨q, rest, hq⟩ := List.exists_cons_of_ne_nil queued
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18, h19, h20,
    h21, h22, h23, h24, h25, h26, h27, h28, h29⟩ := hi
  refine ⟨q, rest, hq, by simp [askFirstA, hq], by grind, by grind, by grind, by grind, ?_, ?_⟩
  · by_contra
    grind
  · simp only [AS.post, askFirstA, hq]
    constructor <;> simp only [] <;> first | omega | grind

/-- Giving the peers that had no room back to the queue keeps `Inv`: they come once items came in
since the last said so. -/
theorem requeue_inv (p : AS) (hi : Inv p) : Inv { p with g := requeueA p.g } := by
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18, h19, h20,
    h21, h22, h23, h24, h25, h26, h27, h28, h29⟩ := hi
  unfold requeueA
  split
  · constructor <;> simp only [] <;> first | omega | grind [List.nodup_append]
  · constructor <;> assumption

/-- The peers moved back to the queue leave the core's other numbers alone. -/
theorem requeue_keeps (a : AG) :
    (requeueA a).items = a.items ∧ (requeueA a).passed = a.passed ∧ (requeueA a).max = a.max ∧
    (requeueA a).found = a.found ∧ (requeueA a).exhausted = a.exhausted ∧
    (requeueA a).searching = a.searching ∧ (requeueA a).underWay = a.underWay := by
  unfold requeueA; split <;> simp

/-- The queue after `requeueA`: unchanged, or (when it was empty, no search was under way and the
peers with no room had seen items come in since) the peers with no room. -/
theorem requeue_next (a : AG) :
    ((requeueA a).next = a.next ∧ (requeueA a).busy = a.busy) ∨
    (a.next = [] ∧ a.searching = false ∧ a.busy ≠ [] ∧ a.passedWhenBusy < a.passed ∧
      (requeueA a).next = a.busy ∧ (requeueA a).busy = []) := by
  unfold requeueA; split
  · rename_i c; right; simp [c.1, c.2.1, c.2.2.1, c.2.2.2]
  · left; simp

/-- When the peers with no room are given back, the queue is what they were. -/
theorem requeue_fires (a : AG)
    (c : a.next = [] ∧ a.searching = false ∧ a.busy ≠ [] ∧ a.passedWhenBusy < a.passed) :
    (requeueA a).next = a.busy := by
  unfold requeueA; simp [c.1, c.2.1, c.2.2.1, c.2.2.2]

/-- What `go` does, for a state that satisfies `Inv`: it answers `act` and leaves the group `a`. -/
theorem go_ok (p : AS) (ev : EvA) (act : Act) (a : AG) (hi : Inv p) (h : goA p.g = (act, a)) :
    Inv (p.post ev act a) ∧
    (act = .search → p.searching = false ∧ 0 < p.room ∧ p.running = []) ∧
    (∀ q, act = .ask q → q < p.found ∧ q ∉ p.running ∧ p.running = [] ∧
      (0 < p.asked q → p.noRoom q = true ∧ p.noRoomAt q < p.passed) ∧
      p.asked q + 1 ≤ p.passed + 1 ∧ p.passed ≠ p.items) ∧
    (act = .finish → p.passed = p.items ∨ (p.running = [] ∧ p.searching = false ∧ p.room = 0 ∧
      ∀ q, q < p.found → 0 < p.asked q ∧ (p.noRoom q = false ∨ p.passed ≤ p.noRoomAny))) ∧
    (p.passed = p.items → act = .finish) ∧
    (act ≠ .finish → (p.post ev act a).running ≠ [] ∨ (p.post ev act a).searching = true) ∧
    (act ≠ .finish → p.passed ≠ p.items) := by
  have hr := requeue_inv p hi
  have hr' := hi
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17, h18, h19, h20,
    h21, h22, h23, h24, h25, h26, h27, h28, h29⟩ := hi
  unfold goA at h
  -- every item is passed on: `go` finishes and leaves the group as it is
  by_cases complete : p.g.passed = p.g.items
  · simp only [complete, ↓reduceIte] at h
    obtain ⟨rfl, rfl⟩ := Prod.mk.inj h
    refine ⟨?_, by simp, by simp, ?_, by simp, by simp, by simp⟩
    · simp only [AS.post]; constructor <;> grind
    · intro _; left; omega
  -- a request is under way: `go` waits for it
  by_cases busy : p.g.underWay ≠ []
  · simp only [complete, busy, ↓reduceIte, ne_eq, not_false_eq_true] at h
    obtain ⟨rfl, rfl⟩ := Prod.mk.inj h
    have not_complete : p.passed ≠ p.items := by rw [h3, h1] at complete; exact complete
    refine ⟨by simpa [AS.post] using hr', by simp, by simp, by simp, fun e => absurd e not_complete, ?_,
      fun _ => not_complete⟩
    · intro _; left; simp [AS.post]; grind
  have idle : p.g.underWay = [] := by simpa using busy
  have not_complete : p.passed ≠ p.items := by rw [h3, h1] at complete; exact complete
  -- nobody is queued, no search is under way and one may find a peer: `go` asks for a search
  by_cases search : p.g.next = [] ∧ p.g.searching = false ∧ p.g.mayFind = true
  · simp only [complete, busy, search, ↓reduceIte, ne_eq] at h
    obtain ⟨rfl, rfl⟩ := Prod.mk.inj h
    simp only [AG.mayFind, Bool.and_eq_true, Bool.not_eq_true', decide_eq_true_eq] at search
    refine ⟨?_, ?_, by simp, by simp, fun e => absurd e not_complete, by simp [AS.post],
      fun _ => not_complete⟩
    · simp only [AS.post]; constructor <;> grind
    · intro _
      refine ⟨by grind, ?_, by grind⟩
      simp only [AS.room]; grind
  simp only [complete, busy, search, ↓reduceIte, ne_eq] at h
  -- otherwise the peers with no room come back if items came in, and `go` asks the first of
  -- the queue, or waits for the search, or finishes
  obtain ⟨k1, k2, k3, k4, k5, k6, k7⟩ := requeue_keeps p.g
  have still_idle : (requeueA p.g).underWay = [] := by rw [k7]; exact idle
  by_cases queued : (requeueA p.g).next ≠ []
  · simp only [queued, ↓reduceIte, not_false_eq_true] at h
    obtain ⟨q, rest, hq, hact, hfound, hfree, hagain, htimes, hsearch, hinv⟩ :=
      ask_first_ok { p with g := requeueA p.g } ev hr queued
    have e1 : act = (askFirstA (requeueA p.g)).1 := by rw [h]
    have e2 : a = (askFirstA (requeueA p.g)).2 := by rw [h]
    subst e1 e2
    refine ⟨hinv, by simp [hact], ?_, by simp [hact], fun e => absurd e not_complete, by simp [AS.post, hact], fun _ => not_complete⟩
    · intro q' hq'
      have : q' = q := by simpa [hact] using hq'.symm
      subst this
      exact ⟨hfound, hfree, by rw [← h7]; exact idle, hagain, htimes, not_complete⟩
  · have empty : (requeueA p.g).next = [] := by simpa using queued
    simp only [empty, not_true_eq_false, ↓reduceIte] at h
    have same_next : p.g.next = [] ∧ (requeueA p.g).busy = p.g.busy := by
      rcases requeue_next p.g with ⟨e1, e2⟩ | ⟨e1, _, e3, _, e5, _⟩
      · exact ⟨by rw [← e1]; exact empty, e2⟩
      · exfalso; rw [e5] at empty; exact e3 empty
    by_cases searching : (requeueA p.g).searching = true
    · simp only [searching, ↓reduceIte] at h
      obtain ⟨rfl, rfl⟩ := Prod.mk.inj h
      have p_searching : p.searching = true := by rw [← h6, ← k6]; exact searching
      refine ⟨by simpa [AS.post] using hr, by simp, by simp, by simp, fun e => absurd e not_complete,
        by simp [AS.post]; right; exact p_searching, fun _ => not_complete⟩
    · simp only [searching] at h
      obtain ⟨rfl, rfl⟩ := Prod.mk.inj h
      have off : (requeueA p.g).searching = false := Bool.eq_false_iff.mpr searching
      have p_idle : p.searching = false := by rw [← h6, ← k6]; exact off
      refine ⟨inv_finished true hr, by simp, by simp, ?_, fun e => absurd e not_complete,
        by simp, by simp⟩
      intro _
      right
      refine ⟨by rw [← h7]; exact idle, p_idle, ?_, ?_⟩
      · simp only [AG.mayFind, Bool.and_eq_true, Bool.not_eq_true', decide_eq_true_eq] at search
        simp only [AS.room]; grind
      · intro q below
        have asked : 0 < p.asked q := by
          by_contra none
          have := h19 q below (by omega)
          rw [same_next.1] at this; simp at this
        refine ⟨asked, ?_⟩
        by_cases gone : p.noRoom q = true
        · right
          have in_busy : q ∈ p.g.busy := h24 q below asked (by rw [same_next.1]; simp) (by rw [← h7]; simp [idle]) gone
          by_contra late
          have fires : p.g.next = [] ∧ p.g.searching = false ∧ p.g.busy ≠ [] ∧
              p.g.passedWhenBusy < p.g.passed := by
            refine ⟨same_next.1, by rw [h6]; exact p_idle, List.ne_nil_of_mem in_busy, ?_⟩
            rw [h25, h3]; omega
          rw [requeue_fires p.g fires] at empty
          exact fires.2.2.1 empty
        · left; simpa using gone

end GroupCore
