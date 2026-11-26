-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the functions of the Rust standard library that the proofs of
-- crates/user-core need to know something about.  Aeneas translates the crate, not the standard
-- library: a function it has no model of becomes an `axiom` nothing is known of.  These three are
-- written here after the sentence of the Rust documentation, and are TRUSTED: the proofs rest on
-- them, so a reviewer checks them against the documentation, next to Spec.lean.
--
-- Why it is needed: `?` on an option (the id of a group line) and `==` on two options (the uid of
-- an entry) are used by the crate.
--
-- Read before this file: nothing.  The names are those Aeneas gives.
--
-- Notation: `Result T` is what a Rust function returns (`ok x`, or a panic: `fail`); `Option` is
-- Rust's (`some x` or `none`).
module
public import Aeneas
@[expose] public section
open Aeneas Aeneas.Std Result Error

/-- `Option::branch` (the `?` operator): "`Some(v)` continues with `v`, `None` breaks out with the
    residual `None`". -/
def core.option.Option.Insts.CoreOpsTry_traitTry.branch {T : Type _} (o : Option T) :
    Result (core.ops.control_flow.ControlFlow (Option Never) T) :=
  ok (match o with
    | some v => .Continue v
    | none => .Break none)

/-- `Option::from_residual` (the `?` operator): "the function returns `None` for the residual
    `None`". -/
def core.option.Option.Insts.CoreOpsTry_traitFromResidualOptionNever.from_residual
    (T : Type _) (_ : Option Never) : Result (Option T) :=
  ok none

/-- `Option<T> == Option<T>`: "two options are equal when both are `None`, or both are `Some` of
    equal values". -/
def core.option.Option.Insts.CoreCmpPartialEqOption.eq {T : Type _}
    (inst : core.cmp.PartialEq T T) (a b : Option T) : Result Bool :=
  match a, b with
  | some x, some y => inst.eq x y
  | none, none => ok true
  | _, _ => ok false
