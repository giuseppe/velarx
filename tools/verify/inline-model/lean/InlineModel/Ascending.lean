-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `Ascending` (Model.lean) gives: every write is between the
-- floor and the ceiling, and a write is never over a later one.
--
-- Why it is needed: the writer is proved to stream once (Layout.lean); the claims about
-- extents (Claims.lean) are read off this one fact.
--
-- Read before this file: Model.lean (`Write`, `Ascending`).
-- Notation: `ws.Pairwise R` says `R a b` holds for every `a` before `b` in `ws`;
-- `ws ++ vs` joins two lists; `w ∈ ws` is "w is one of ws".
import InlineModel.Model

namespace InlineModel

/-- Going up from `floor`, the ceiling is not below the floor. -/
theorem Ascending.floor_le {floor ceiling : Nat} {ws : List Write}
    (up : Ascending floor ws ceiling) : floor ≤ ceiling := by
  induction ws generalizing floor with
  | nil => exact up
  | cons w ws ih =>
    have := ih up.2
    have := up.1
    omega

/-- Every write of an ascending list is between the floor and the ceiling. -/
theorem Ascending.bounds {floor ceiling : Nat} {ws : List Write}
    (up : Ascending floor ws ceiling) : ∀ w ∈ ws, floor ≤ w.start ∧ w.start + w.len ≤ ceiling := by
  induction ws generalizing floor with
  | nil => intro w h; cases h
  | cons v ws ih =>
    intro w h
    have after := up.2.floor_le
    have first := up.1
    rcases List.mem_cons.mp h with rfl | h
    · omega
    · have := ih up.2 w h
      omega

/-- A write of an ascending list ends before every later one starts. -/
theorem Ascending.apart {floor ceiling : Nat} {ws : List Write}
    (up : Ascending floor ws ceiling) :
    ws.Pairwise fun a b => a.start + a.len ≤ b.start := by
  induction ws generalizing floor with
  | nil => exact .nil
  | cons w ws ih =>
    refine .cons ?_ (ih up.2)
    intro b hb
    exact (up.2.bounds b hb).1

/-- A lower floor or a higher ceiling is still ascending. -/
theorem Ascending.widen {floor ceiling floor' ceiling' : Nat} {ws : List Write}
    (up : Ascending floor ws ceiling) (below : floor' ≤ floor) (above : ceiling ≤ ceiling') :
    Ascending floor' ws ceiling' := by
  induction ws generalizing floor floor' with
  | nil => exact Nat.le_trans (Nat.le_trans below up) above
  | cons w ws ih => exact ⟨Nat.le_trans below up.1, ih up.2 (Nat.le_refl _)⟩

/-- Two ascending lists, the second from where the first ends, are one. -/
theorem Ascending.append {floor middle ceiling : Nat} {a b : List Write}
    (first : Ascending floor a middle) (second : Ascending middle b ceiling) :
    Ascending floor (a ++ b) ceiling := by
  induction a generalizing floor with
  | nil => exact second.widen first (Nat.le_refl _)
  | cons w ws ih => exact ⟨first.1, ih first.2⟩

/-- A byte that no write of `ws` covers is the one below. -/
theorem foldl_write_untouched (ws : List Write) (below : Nat → Nat) (pos : Nat)
    (apart : ∀ u ∈ ws, pos < u.start ∨ u.start + u.len ≤ pos) :
    ws.foldl write below pos = below pos := by
  induction ws generalizing below with
  | nil => rfl
  | cons u ws ih =>
    rw [List.foldl_cons, ih (write below u) (fun v mem => apart v (.tail _ mem))]
    have := apart u (.head _)
    unfold write
    split
    · omega
    · rfl

/-- Reading back: in an ascending list of writes, the byte `i` of a write is what it wrote,
whatever the image was below: no later write is over it, and none before is after it. -/
theorem Ascending.reads {floor ceiling : Nat} {ws : List Write}
    (up : Ascending floor ws ceiling) (below : Nat → Nat) :
    ∀ w ∈ ws, ∀ i < w.len, ws.foldl write below (w.start + i) = w.bytes i := by
  induction ws generalizing floor below with
  | nil => intro w mem; cases mem
  | cons v ws ih =>
    intro w mem i small
    rw [List.foldl_cons]
    rcases List.mem_cons.mp mem with rfl | mem
    · -- the write itself: the writes after it start after its end
      rw [foldl_write_untouched ws _ _ fun u mu =>
        Or.inl (by have := (up.2.bounds u mu).1; omega)]
      have inside : w.start ≤ w.start + i ∧ w.start + i < w.start + w.len := by omega
      simp [write, inside]
    · -- a later write: the induction applies, the one before is below it
      exact ih up.2 (write below v) w mem i small

end InlineModel
