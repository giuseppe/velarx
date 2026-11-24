-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the two functions of the Rust standard library
-- that the proofs of crates/pull-core need to know something about.
-- Aeneas translates the crate, but not the standard library: a function
-- of the library it has no model of becomes an `axiom` nothing is known
-- of, and the proofs hold whatever it does (../../run makes those from
-- the template Aeneas writes, but for the names defined here).
--
-- Why it is needed: `pull_at` finds a pull with `position`, and `end` and
-- `forget` drop pulls and claims with `Vec::retain`; the claims of Spec.lean
-- follow what they do.  Each is written here by hand, after the sentence of
-- the Rust documentation, quoted in its comment, and is TRUSTED: the proofs
-- rest on it, so it is what a reviewer checks against the documentation,
-- next to Spec.lean.  They are the models lazy-core has, word for word (each
-- is a loop that calls the predicate on the elements in order, `positionFrom`
-- and `retainFrom`; each crate has its own file of models).
--
-- Read before this file: nothing.  The names are those Aeneas gives.
--
-- Notation: `Result T` is what a Rust function returns (`ok x`, or a
-- panic: `fail`); `do ... let x ← m ...` is "run `m`, call its result
-- `x`, go on"; `v.val` is the list inside a vector; `l.Sublist m` is "`l`
-- is `m` with some elements left out".
module
public import Aeneas
@[expose] public section
open Aeneas Aeneas.Std Result Error

/-- Helper of `position` below: the search from the `i`th element on.  It calls
    `pred` on the elements one by one and stops at the first it says yes to.
    It returns that element's index and the iterator after it, or `none` and
    the iterator at the end. -/
def positionFrom {T : Type _} {P : Type _}
    (inst : core.ops.function.FnMut P T Bool) (s : Slice T) (pred : P) (i : Nat) :
    Result ((Option Std.Usize) × (core.slice.iter.Iter T)) :=
  if h : i < s.val.length then do
    let (b, pred1) ← inst.call_mut pred s.val[i]
    if b then ok (some (Std.Usize.ofNatCore i (by scalar_tac)), ⟨s, i + 1⟩)
    else positionFrom inst s pred1 (i + 1)
  else ok (none, ⟨s, i⟩)
termination_by s.val.length - i

/-- `slice::Iter::position`: "Searches for an element in an iterator,
    returning its index", counted from where the iterator is; the
    iterator is left after the element found, or at its end. -/
def core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.position
    {T : Type _} {P : Type _} (inst : core.ops.function.FnMut P T Bool)
    (it : core.slice.iter.Iter T) (pred : P) :
    Result ((Option Std.Usize) × (core.slice.iter.Iter T)) := do
  let (o, it1) ← positionFrom inst it.slice pred it.i
  -- (the index counts from where the iterator is)
  match o with
  | some n => ok (some (Std.Usize.ofNatCore (n.val - it.i) (by scalar_tac)), it1)
  | none => ok (none, it1)

/-- Helper of `Vec::retain` below: the elements kept, in order.  It calls the predicate on
    the elements one by one, from the first, and keeps those it says yes to; the state
    of the predicate goes on from one call to the next.  What it returns is the kept list
    together with the fact that it is a sublist of the elements (a list with some left out).
    The fact is part of the definition on purpose: `Vec::retain` below must build a vector
    from the kept list, and a vector holds at most `Usize.max` elements; with the fact in the
    type, the model needs no test that cannot fail and no lemma outside the definition. -/
def retainFrom {T : Type _} {F : Type _}
    (inst : core.ops.function.FnMut F T Bool) :
    (l : List T) → F → Result { r : List T // r.Sublist l }
  | [], _ => ok ⟨[], .slnil⟩
  | x :: rest, f => do
    let (b, f1) ← inst.call_mut f x
    let kept ← retainFrom inst rest f1
    ok (if b then ⟨x :: kept.val, kept.property.cons_cons x⟩
        else ⟨kept.val, kept.property.cons x⟩)

/-- `Vec::retain`: "Retains only the elements specified by the predicate. ... This method
    operates in place, visits each element exactly once in the original order, and
    preserves the order of the retained elements." -/
def alloc.vec.Vec.retain {T : Type _} (_A : Type _) {F : Type _}
    (inst : core.ops.function.FnMut F T Bool) (v : alloc.vec.Vec T) (f : F) :
    Result (alloc.vec.Vec T) := do
  let kept ← retainFrom inst v.val f
  ok (alloc.vec.Vec.from kept.val (by
    have := v.property
    have := kept.property.length_le
    omega))
