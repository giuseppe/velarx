-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the functions of the Rust standard library that
-- the proofs of crates/tarsplit-header need to know something about.
-- Aeneas translates the crate, but not the standard library: a function
-- of the library it has no model of becomes an `axiom` nothing is known
-- of, and the proofs hold whatever it does (../../run makes those from
-- the template Aeneas writes, but for the names defined here).
--
-- Why it is needed: the claims of Spec.lean follow what these functions
-- do (a range says whether a byte is in it, `checked_next_multiple_of`
-- rounds up to a block, `?` on an option leaves the function on `None`).
-- Each is written here by hand, after the sentence of the Rust
-- documentation, quoted in its comment, and is TRUSTED: the proofs rest
-- on it, so it is what a reviewer checks against the documentation,
-- next to Spec.lean.
--
-- Read before this file: nothing.  The names are those Aeneas gives.
--
-- Notation: `Result T` is what a Rust function returns (`ok x`, or a
-- panic: `fail`); `do ... let x ← m ...` is "run `m`, call its result
-- `x`, go on"; `x.val` is the number a machine integer is; `Option` is
-- Rust's (`some x` or `none`).
module
public import Aeneas
@[expose] public section
open Aeneas Aeneas.Std Result Error

/-- `RangeInclusive::contains`: "Returns `true` if `item` is contained in the
    range. [...] This method always returns `false` after iteration has
    finished."  That is `start <= item <= end`; once the range is exhausted
    its end is `start` excluded, as `end_bound` of the library says, so
    nothing is in it. -/
def core.ops.range.RangeInclusive.contains
    {Idx : Type _} {U : Type _} (_ : core.cmp.PartialOrd Idx Idx)
    (startLe : core.cmp.PartialOrd Idx U) (endCmp : core.cmp.PartialOrd U Idx)
    (r : core.ops.range.RangeInclusive Idx) (item : U) : Result Bool := do
  let lo ← startLe.le r.start item
  if lo then
    if r.exhausted then endCmp.lt item r.start else endCmp.le item r.«end»
  else ok false

/-- `u64::checked_next_multiple_of`: "Calculates the smallest value greater than
    or equal to `self` that is a multiple of `rhs`.  Returns `None` if `rhs` is
    zero or the operation would result in overflow." -/
def core.num.U64.checked_next_multiple_of (x y : Std.U64) : Result (Option Std.U64) :=
  let m := (x.val + y.val - 1) / y.val * y.val
  if y.val ≠ 0 ∧ m ≤ Std.U64.max then ok (some ⟨BitVec.ofNat _ m⟩) else ok none

/-- `Option::branch` (the `?` operator): "`Some(v)` continues with `v`, `None`
    breaks out with the residual `None`". -/
def core.option.Option.Insts.CoreOpsTry_traitTry.branch {T : Type _} (o : Option T) :
    Result (core.ops.control_flow.ControlFlow (Option Never) T) :=
  ok (match o with
    | some v => .Continue v
    | none => .Break none)

/-- `Option::from_residual` (the `?` operator): "the function returns `None`
    for the residual `None`". -/
def core.option.Option.Insts.CoreOpsTry_traitFromResidualOptionNever.from_residual
    (T : Type _) (_ : Option Never) : Result (Option T) :=
  ok none

/-- `<[T]>::as_chunks`: "Splits the slice into a slice of `N`-element arrays,
    starting at the beginning of the slice, and a remainder slice with length
    strictly less than `N`."  "Panics if `N` is zero."  The chunk `k` is the
    `N` elements from `k * N`. -/
def core.slice.Slice.as_chunks {T : Type _} (N : Std.Usize) (s : Slice T) :
    Result ((Slice (Array T N)) × (Slice T)) :=
  if hN : N.val = 0 then fail panic else
  have := s.property
  let n := s.val.length / N.val
  have hn : n * N.val ≤ s.val.length := Nat.div_mul_le_self _ _
  have hnl : n ≤ s.val.length := Nat.div_le_self _ _
  ok (Slice.from (List.ofFn fun k : Fin n => Array.make N ((s.val.drop (k * N.val)).take N.val) (by
        have : (k.val + 1) * N.val ≤ n * N.val := Nat.mul_le_mul_right _ k.isLt
        simp only [List.length_take, List.length_drop]
        rw [Nat.add_mul] at this
        omega)) (by simp; scalar_tac),
      Slice.from (s.val.drop (n * N.val)) (by simp; scalar_tac))
