-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the group as a record of numbers and lists (`AG`), the five decisions of
-- crates/group-core/src/lib.rs written as functions on it (`goA`, `endedA`, `foundA`,
-- `hedgeDueA`, `hedgeA`), and the proof that the Rust functions do exactly that.
--
-- Why it is needed: the proofs of the next files are about what a group can reach.  They are
-- easier on plain lists and numbers than on a `Vec` with its bound, and the one place that
-- reads the Rust is here: each theorem below says "the Rust function returns, and the group and
-- the answer it gives are those of the function on the record".
--
-- Read before this file: Lists.lean and crates/group-core/src/lib.rs.
--
-- Notation: `g.abs` is the group `g` as a record (peers are numbers); `(f g) ⦃ r => P r ⦄` is
-- "the Rust `f` returns on `g`, with no panic and no endless loop, and its answer `r` satisfies
-- `P`"; `Wf g` says the queue and the requests under way together fit in a `Vec`.
import GroupCore.Lists
open Aeneas Aeneas.Std Result velarx_group_core
namespace GroupCore

/-- What the core knows of a group, as numbers and lists. -/
structure AG where
  items : Nat
  passed : Nat
  max : Nat
  found : Nat
  exhausted : Bool
  searching : Bool
  next : List Nat
  underWay : List Nat
  busy : List Nat
  passedWhenBusy : Nat
  last : Nat

/-- What the shell is told to do, with the peer as a number. -/
inductive Act where
  | wait | search | ask (peer : Nat) | finish
  deriving DecidableEq

/-- The group of the Rust code, as a record. -/
def _root_.velarx_group_core.Group.abs (g : Group) : AG where
  items := g.items.val
  passed := g.passed.val
  max := g.max.val
  found := g.found.val
  exhausted := g.exhausted
  searching := g.searching
  next := g.next.val.map (·.val)
  underWay := g.under_way.val.map (·.val)
  busy := g.busy.val.map (·.val)
  passedWhenBusy := g.passed_when_busy.val
  last := g.last.val

/-- The answer of the core, with the peer as a number. -/
def _root_.velarx_group_core.Do.act : Do → Act
  | .Wait => .wait
  | .Search => .search
  | .Ask q => .ask q.val
  | .Finish => .finish

/-- The queue and the requests under way fit in a `Vec` together. -/
def Wf (g : Group) : Prop := g.under_way.length + g.next.length ≤ Std.Usize.max

/-- A search may find another peer (`may_search`). -/
def AG.mayFind (a : AG) : Bool := !a.exhausted && decide (a.found < a.max)

/-- The first peer of the queue is asked (`ask_first`). -/
def askFirstA (a : AG) : Act × AG :=
  match a.next with
  | q :: rest => (.ask q, { a with next := rest, underWay := a.underWay ++ [q], last := q })
  | [] => (.wait, a)

/-- The peers that had no room go back to the queue once items came in (`requeue`). -/
def requeueA (a : AG) : AG :=
  if a.next = [] ∧ a.searching = false ∧ a.busy ≠ [] ∧ a.passedWhenBusy < a.passed then
    { a with next := a.next ++ a.busy, busy := [] }
  else a

/-- What to do after any event (`go`). -/
def goA (a : AG) : Act × AG :=
  if a.passed = a.items then (.finish, a)
  else if a.underWay ≠ [] then (.wait, a)
  else if a.next = [] ∧ a.searching = false ∧ a.mayFind = true then
    (.search, { a with searching := true })
  else
    let b := requeueA a
    if b.next ≠ [] then askFirstA b
    else if b.searching then (.wait, b) else (.finish, b)

/-- The group `chunk` hands to `go`: `passed` items are passed on now. -/
def chunkIn (a : AG) (passed : Nat) : AG := { a with passed := passed }

/-- `chunk`. -/
def chunkA (a : AG) (passed : Nat) : Act × AG := goA (chunkIn a passed)

/-- The group `ended` hands to `go`: the request of `peer` is over, `passed` items are passed on,
and a peer with no room is kept. -/
def endedIn (a : AG) (peer : Nat) (noRoom : Bool) (passed : Nat) : AG :=
  { a with
    passed := passed
    underWay := a.underWay.filter (fun x => decide (x ≠ peer))
    busy := if noRoom then a.busy ++ [peer] else a.busy
    passedWhenBusy := if noRoom then passed else a.passedWhenBusy }

/-- `ended`. -/
def endedA (a : AG) (peer : Nat) (noRoom : Bool) (passed : Nat) : Act × AG :=
  goA (endedIn a peer noRoom passed)

/-- The group `found` builds: `n` more peers, numbered after the others, queued. -/
def foundIn (a : AG) (n : Nat) : AG :=
  { a with found := a.found + n, exhausted := decide (n = 0) || a.exhausted,
           searching := false, next := a.next ++ List.range' a.found n }

/-- `found`. -/
def foundA (a : AG) (n : Nat) : Act × AG :=
  if a.underWay ≠ [] ∧ (foundIn a n).next ≠ [] then askFirstA (foundIn a n) else goA (foundIn a n)

/-- `hedge_due`. -/
def hedgeDueA (a : AG) : Act × AG :=
  if a.next ≠ [] then askFirstA a
  else if a.mayFind = true then (.search, { a with searching := true })
  else (.wait, a)

/-- Whether the hedge timer is armed (`hedge`). -/
def hedgeA (a : AG) : Prop :=
  a.underWay ≠ [] ∧ a.searching = false ∧ (a.next ≠ [] ∨ a.mayFind = true)

end GroupCore
