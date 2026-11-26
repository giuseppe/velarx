-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the functions that the proofs of crates/limit-core use and that Aeneas
-- has no model of.  Aeneas turns such a function into an `axiom` nothing is known of, so each is
-- written here after the sentence of the Rust documentation, and is TRUSTED: a reviewer checks
-- them against it, next to Spec.lean.  They are three: the two halves of `?` on an option
-- (`exponent(..)?` of `decimal`), and `float::weight` (float.rs), the weight of a count of CPU
-- shares as crun computes it with `f64` (`log2`, `powf`, `ceil`), which `../options` makes Charon
-- take as opaque: Aeneas has no model of floating point numbers.
--
-- Why it is needed: `decimal` and `weight_of_shares` call them.  The model of `float::weight`
-- says that the function RETURNS some number (a float operation does not panic or
-- loop, and `as u64` of a float saturates), and nothing else.  The number is that of an `opaque`
-- function of the count: no proof can use what it is, so every claim of Spec.lean about
-- `weight_of_shares` holds for ANY number the real function gives.  What does depend on the
-- number (the weight of a count of shares, that it grows with the shares, that
-- `shares_of_weight` is the inverse of it) is NOT claimed there: the tests of the crate check it.
--
-- Read before this file: nothing.
--
-- Notation: `Result T` is what a Rust function returns (`ok x`, or a panic: `fail`).
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

/-- The number `float::weight` gives for a count of shares: some function of the count, which one
    is not said (`opaque`: no proof can look into it, so it stands for any function). -/
opaque float.weightOf : Std.U64 → Std.U64

/-- `float::weight`: it returns a number of `u64`, which one is not said. -/
def float.weight (shares : Std.U64) : Result Std.U64 :=
  ok (float.weightOf shares)
