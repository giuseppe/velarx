-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the loop around the core, the "shell" of rules.rs, as a record of numbers
-- and lists (`AS`), with one step: what the loop does to what it knows when an event comes, what
-- the core answers (Model.lean), and what the loop does to what it knows with the answer.  `ReachA`
-- is "the states a group can be in": the start, and every step the loop may make.
--
-- Why it is needed: the claims of Spec.lean are about the Rust core and the loop of Spec.lean
-- (which holds a `Group`); the proofs are about this copy (which holds the group as lists), because
-- the lists can be taken apart.  Link.lean ties the two.
--
-- Read before this file: Model.lean, and crates/group-core/src/rules.rs (`Shell`, `tell`).
--
-- Notation: `s.pre ev` is the loop's knowledge once the event is known and before the core is
-- asked; `s.after ev act a` adds what the answer `act` and the new group `a` change.
import GroupCore.Model
namespace GroupCore

/-- What the loop knows about the group, besides the group itself (rules.rs, `Shell`). -/
structure AS where
  g : AG
  items : Nat
  max : Nat
  running : List Nat
  searching : Bool
  hedged : Bool
  exhausted : Bool
  passed : Nat
  found : Nat
  asked : Nat → Nat
  noRoomAt : Nat → Nat
  noRoom : Nat → Bool
  noRoomAny : Nat
  finished : Bool

/-- What the loop may report. -/
inductive EvA where
  | chunk (passed : Nat)
  | ended (peer : Nat) (noRoom : Bool) (passed : Nat)
  | found (n : Nat)
  | hedgeDue
  deriving DecidableEq

/-- The peers a search may still find, as the loop sees it. -/
def AS.room (s : AS) : Nat := if s.exhausted then 0 else s.max - s.found

/-- The loop may report this event now. -/
def EnabledA (s : AS) : EvA → Prop
  | .chunk p => s.running ≠ [] ∧ s.passed ≤ p ∧ p ≤ s.items
  | .ended q _ p => q ∈ s.running ∧ s.passed ≤ p ∧ p ≤ s.items
  | .found n => s.searching = true ∧ n ≤ s.room
  | .hedgeDue => hedgeA s.g

/-- What the loop knows once it has the event, before the core answers. -/
def AS.pre (s : AS) : EvA → AS
  | .chunk p => { s with passed := p, g := chunkIn s.g p }
  | .ended q nr p =>
    { s with
      passed := p
      running := s.running.filter (fun x => decide (x ≠ q))
      noRoom := Function.update s.noRoom q nr
      noRoomAt := if nr then Function.update s.noRoomAt q p else s.noRoomAt
      noRoomAny := if nr then p else s.noRoomAny
      g := endedIn s.g q nr p }
  | .found n =>
    { s with searching := false, exhausted := decide (n = 0), found := s.found + n,
             g := foundIn s.g n }
  | .hedgeDue => s

/-- What the core answers, and the group it leaves, as the models of Model.lean say: after the
event, `go` decides (or, when a search finds peers while a request is under way, the first of them
is asked at once), and the hedge timer asks or starts a search. -/
def AS.answer (s : AS) (ev : EvA) : Act × AG :=
  let g := (s.pre ev).g
  match ev with
  | .chunk _ => goA g
  | .ended .. => goA g
  | .found _ => if s.g.underWay ≠ [] ∧ g.next ≠ [] then askFirstA g else goA g
  | .hedgeDue => hedgeDueA s.g

/-- What the loop adds to what it knows once the core answered `act` and left the group `a`
(`ev` is the event it answered). -/
def AS.post (p : AS) (ev : EvA) (act : Act) (a : AG) : AS :=
  let p := { p with g := a }
  match act with
  | .wait => p
  | .search => { p with searching := true, hedged := decide (ev = .hedgeDue) }
  | .ask q => { p with asked := Function.update p.asked q (p.asked q + 1), running := p.running ++ [q] }
  | .finish => { p with finished := true }

/-- What the loop knows after the event and the answer. -/
def AS.after (s : AS) (ev : EvA) (act : Act) (a : AG) : AS := (s.pre ev).post ev act a

/-- The loop's knowledge when a group starts: nothing found, a search under way. -/
def AS.start (items passed max : Nat) : AS where
  g := { items, passed, max, found := 0, exhausted := false, searching := true, next := [],
         underWay := [], busy := [], passedWhenBusy := 0, last := 0 }
  items := items
  max := max
  running := []
  searching := true
  hedged := false
  exhausted := false
  passed := passed
  found := 0
  asked := fun _ => 0
  noRoomAt := fun _ => 0
  noRoom := fun _ => false
  noRoomAny := 0
  finished := false

/-- The states a group can be in: the start, and any step of the loop from a state that is not
finished. -/
inductive ReachA : AS → Prop
  | start (items passed max : Nat) (below : passed < items) : ReachA (AS.start items passed max)
  | step (s : AS) (ev : EvA) : ReachA s → s.finished = false → EnabledA s ev →
      ReachA (s.after ev (s.answer ev).1 (s.answer ev).2)

end GroupCore
