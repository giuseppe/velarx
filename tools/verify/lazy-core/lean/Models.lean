-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the functions of the Rust standard library that
-- the proofs need to know something about.  Aeneas translates the
-- crate, but not the standard library: a function of the library it
-- has no model of becomes an `axiom` nothing is known of, and the proofs
-- hold whatever it does (../../run makes those from the template Aeneas
-- writes, but for the names defined here).
--
-- Why it is needed: the claims of Spec.lean follow what some library
-- functions do (`position` finds the first element, `any` says whether there is one,
-- `remove` removes one, `checked_shl` and `saturating_mul` compute the wait of a retry).
-- Each is written here by hand, after the sentence of the Rust
-- documentation, quoted in its comment, and is TRUSTED: the proofs
-- rest on it, so it is what a reviewer checks against the
-- documentation, next to Spec.lean.  A model is a few lines, but for
-- `position` and `retain`: `position` is a search loop over the elements (`positionFrom`),
-- so it is longer (`any` is that search, said yes or no); `retain` is a loop that calls the
-- predicate on each element in order (`retainFrom`).
--
-- Read before this file: nothing.  The names are those Aeneas gives
-- (`core.slice.iter.Iter.Insts...position` is `<[T]>::iter().position`).
--
-- Notation: `Result T` is what a Rust function returns (`ok x`, or a
-- panic: `fail`); `do ... let x ← m ...` is "run `m`, call its result
-- `x`, go on"; `s.val` is the list inside a slice or vector, `s.val[i]`
-- its `i`th element; `x.val` is the number a machine integer is;
-- `Option` is Rust's (`some x` or `none`).
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

/-- `slice::Iter::any`: "Tests if any element of the iterator matches a predicate.
    ... It applies this closure to each element of the iterator, and if any of them
    return `true`, then so does `any()`. ... `any()` is short-circuiting; in other
    words, it will stop processing as soon as it finds a `true`".  It is `position`
    that found something: the iterator is left after the element found, or at its end. -/
def core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.any
    {T : Type _} {P : Type _} (inst : core.ops.function.FnMut P T Bool)
    (it : core.slice.iter.Iter T) (pred : P) :
    Result (Bool × (core.slice.iter.Iter T)) := do
  let (o, it1) ← core.slice.iter.Iter.Insts.CoreIterTraitsIteratorIteratorSharedAT.position
    inst it pred
  ok (o.isSome, it1)

/-- `Option::filter`: "Returns `None` if the option is `None`, otherwise calls
    `predicate` with the wrapped value and returns: `Some(t)` if `predicate`
    returns `true` (where `t` is the wrapped value), and `None` if `predicate`
    returns `false`." -/
def core.option.Option.filter {T : Type _} {P : Type _}
    (inst : core.ops.function.FnOnce P T Bool) (o : Option T) (predicate : P) :
    Result (Option T) :=
  match o with
  | none => ok none
  | some t => do
    let b ← inst.call_once predicate t
    ok (if b then some t else none)

/-- `Vec::remove`: "Removes and returns the element at position `index`
    within the vector, shifting all elements after it to the left.
    Panics if `index` is out of bounds." -/
def alloc.vec.Vec.remove
    {T : Type _} (_A : Type _) (v : alloc.vec.Vec T) (i : Std.Usize) :
    Result (T × (alloc.vec.Vec T)) :=
  if h : i.val < v.val.length then
    ok (v.val[i.val], alloc.vec.Vec.from (v.val.eraseIdx i.val) (by
      have := v.property
      have := List.length_eraseIdx_le v.val i.val
      omega))
  else fail panic

/-- `u64::checked_shl`: "Checked shift left. Computes `self << rhs`,
    returning `None` if `rhs` is larger than or equal to the number of
    bits in `self`." -/
def core.num.U64.checked_shl (x : Std.U64) (n : Std.U32) : Result (Option Std.U64) :=
  ok (if n.val < 64 then some ⟨x.bv <<< n.val⟩ else none)

/-- `u64::saturating_mul`: "Saturating integer multiplication. Computes
    `self * rhs`, saturating at the numeric bounds instead of
    overflowing." -/
def core.num.U64.saturating_mul (x y : Std.U64) : Result Std.U64 :=
  ok ⟨BitVec.ofNat _ (min Std.U64.max (x.val * y.val))⟩

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

/-- `Vec::default`: "Creates an empty `Vec<T>`." -/
def alloc.vec.Vec.Insts.CoreDefaultDefault.default (T : Type _) :
    Result (alloc.vec.Vec T) :=
  ok (alloc.vec.Vec.new T)

/-- `mem::take`: "Replaces `dest` with the default value of `T`, returning the previous
    `dest` value." -/
def core.mem.take {T : Type _} (inst : core.default.Default T) (dest : T) :
    Result (T × T) := do
  let d ← inst.default
  ok (dest, d)
