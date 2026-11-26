-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs about `parse_size` and what it calls (`decimal`, `exponent`, `unit_shift`): they return on every text, and the answer is below `i64::MAX`.
-- Why it is needed: the size is a text of a client and is read in a 128-bit number; every counter and every exponent must stay in its type.
-- Read before this file: Cpuset.lean.
-- Notation: `f x ⦃ r => P r ⦄` is "the Rust `f` returns on `x`, with no panic and no endless loop,
--    and its answer `r` satisfies `P`"; `step` goes through one line of the Rust function and
--    `scalar_tac` proves a fact about machine numbers by arithmetic; `↑x` (or `x.val`) is the number
--    a machine integer is.
import LimitCore.Cpuset
open Aeneas Aeneas.Std Aeneas.Data.Coinductive Result velarx_limit_core
namespace LimitCore

/-- `lower` returns: it adds 32 only to the capital letters. -/
@[local step] theorem lower_spec (b : Std.U8) : lower b ⦃ _ => True ⦄ := by
  unfold lower
  step*

/-- `unit_shift` returns on any text, and a shift it answers is at most 50, which `u128` takes. -/
theorem unit_shift_spec (u : Slice Std.U8) : unit_shift u ⦃ r => ∀ n, r = some n → n.val ≤ 50 ⦄ := by
  unfold unit_shift
  step*

set_option linter.unusedTactic false in
set_option linter.unreachableTactic false in
/-- The loop of the digits of the number: it ends, and the exponent it counts stays within the
places read (at most one for each byte, so far from the ends of `i64`). -/
theorem decimal_loop_spec (s : Slice Std.U8) (i : Std.Usize) (m : Std.U64) (exp : Std.I64)
    (d : Std.Usize) (frac : Bool) (hs : s.length < 2 ^ 62)
    (h : i.val ≤ s.length ∧ -(i.val : Int) ≤ exp.val ∧ exp.val ≤ i.val ∧ d.val ≤ i.val) :
    decimal_loop s i m exp d frac ⦃ r =>
      i.val ≤ r.1.val ∧ r.1.val ≤ s.length ∧ -(r.1.val : Int) ≤ r.2.2.1.val ∧
        r.2.2.1.val ≤ r.1.val ∧ r.2.2.2.val ≤ r.1.val ⦄ := by
  unfold decimal_loop
  apply loop.spec_decr_nat
    (fun (q : Std.Usize × Std.U64 × Std.I64 × Std.Usize × Bool) => s.length - q.1.val)
    (fun (q : Std.Usize × Std.U64 × Std.I64 × Std.Usize × Bool) => i.val ≤ q.1.val ∧
      q.1.val ≤ s.length ∧ -(q.1.val : Int) ≤ q.2.2.1.val ∧ q.2.2.1.val ≤ q.1.val ∧
      q.2.2.2.1.val ≤ q.1.val)
    (fun (r : Std.Usize × Std.U64 × Std.I64 × Std.Usize) =>
      i.val ≤ r.1.val ∧ r.1.val ≤ s.length ∧ -(r.1.val : Int) ≤ r.2.2.1.val ∧
        r.2.2.1.val ≤ r.1.val ∧ r.2.2.2.val ≤ r.1.val)
  · rintro ⟨i1, m1, e1, d1, f1⟩ ⟨h1, h2, h3, h4, h5⟩
    simp only at h1 h2 h3 h4 h5 ⊢
    unfold decimal_loop.body
    step*
    all_goals (try scalar_tac)
    all_goals (try split)
    all_goals (try step*)
    all_goals (try scalar_tac)
    all_goals (try split)
    all_goals (try step*)
    all_goals (try scalar_tac)
    all_goals (try split)
    all_goals (try step*)
    all_goals (try scalar_tac)
  · exact ⟨le_refl _, h.1, h.2.1, h.2.2.1, h.2.2.2⟩


/-- A byte keeps its value as an `i64`. -/
@[scalar_tac_simps, simp]
theorem hcast_u8_i64 (u : Std.U8) : (UScalar.hcast IScalarTy.I64 u).val = u.val := by
  have h := u.hBounds
  have hb : (((2 ^ IScalarTy.I64.numBits : Nat)) : Int) = 2 ^ 64 := by rfl
  rw [UScalar.hcast_val_eq, Int.bmod_def, hb]
  simp only [UScalarTy.numBits] at h
  split_ifs <;> omega

set_option linter.unusedTactic false in
set_option linter.unreachableTactic false in
/-- The loop of the digits of the exponent: it ends, the exponent stays between 0 and 10000009 (it
stops growing once it is a million) and the digits counted are at most the places read. -/
theorem exp_loop_spec (s : Slice Std.U8) (i : Std.Usize) (e : Std.I64) (d : Std.Usize)
    (h : i.val ≤ s.length ∧ 0 ≤ e.val ∧ e.val ≤ 10000009 ∧ d.val ≤ i.val) :
    exponent_loop s i e d ⦃ r =>
      i.val ≤ r.1.val ∧ r.1.val ≤ s.length ∧ 0 ≤ r.2.1.val ∧ r.2.1.val ≤ 10000009 ∧
        r.2.2.val ≤ r.1.val ⦄ := by
  unfold exponent_loop
  apply loop.spec_decr_nat
    (fun (q : Std.Usize × Std.I64 × Std.Usize) => s.length - q.1.val)
    (fun (q : Std.Usize × Std.I64 × Std.Usize) => i.val ≤ q.1.val ∧ q.1.val ≤ s.length ∧
      0 ≤ q.2.1.val ∧ q.2.1.val ≤ 10000009 ∧ q.2.2.val ≤ q.1.val)
    (fun (r : Std.Usize × Std.I64 × Std.Usize) =>
      i.val ≤ r.1.val ∧ r.1.val ≤ s.length ∧ 0 ≤ r.2.1.val ∧ r.2.1.val ≤ 10000009 ∧
        r.2.2.val ≤ r.1.val)
  · rintro ⟨i1, e1, d1⟩ ⟨h1, h2, h3, h4, h5⟩
    simp only at h1 h2 h3 h4 h5 ⊢
    unfold exponent_loop.body
    step*
    all_goals (have hd := b_post.mp ‹_›; try scalar_tac)
    all_goals (try split)
    all_goals (try step*)
    all_goals (try scalar_tac)
  · exact ⟨le_refl _, h.1, h.2.1, h.2.2.1, h.2.2.2⟩

attribute [local step] decimal_loop_spec exp_loop_spec

/-- `exponent` returns on any bytes, and the exponent it reads is between 0 and 10000009 in
absolute value. -/
theorem exponent_spec (s : Slice Std.U8) (i : Std.Usize) (h : i.val ≤ s.length) :
    exponent s i ⦃ r => ∀ e, r = some e → -10000009 ≤ e.val ∧ e.val ≤ 10000009 ⦄ := by
  unfold exponent
  have hmin : (I64.min : Int) = -(2 ^ 63) := by simp [I64.min_def, I64.numBits]
  dsimp only
  split
  · step as ⟨i3, h3⟩
    split
    · step*
    · split
      · step*
        intro e he; cases he; scalar_tac
      · step*
  · step*

/-- The end of `decimal` after an `e`: the exponent is read and added, or there is no number. -/
theorem exp_tail (s : Slice Std.U8) (neg : Bool) (m : Std.U64) (exp : Std.I64) (i5 : Std.Usize)
    (hi5 : i5.val ≤ s.length) (hs : s.length < 2 ^ 62) (he : -(s.length : Int) ≤ exp.val ∧ exp.val ≤ s.length) :
    (do
      let o ← exponent s i5
      let cf ← core.option.Option.Insts.CoreOpsTry_traitTry.branch o
      match cf with
      | core.ops.control_flow.ControlFlow.Continue val => do
        let i6 ← exp + val
        ok (some (neg, m, i6))
      | core.ops.control_flow.ControlFlow.Break residual =>
        core.option.Option.Insts.CoreOpsTry_traitFromResidualOptionNever.from_residual
          (Bool × Std.U64 × Std.I64) residual) ⦃ r => ∀ t, r = some t →
      -(2 ^ 62 + 10000009 : Int) ≤ t.2.2.val ∧ t.2.2.val ≤ 2 ^ 62 + 10000009 ⦄ := by
  step with exponent_spec s i5 hi5 as ⟨o, ho⟩
  cases o with
  | none =>
    simp [core.option.Option.Insts.CoreOpsTry_traitTry.branch,
      core.option.Option.Insts.CoreOpsTry_traitFromResidualOptionNever.from_residual, WP.spec_ok]
  | some v =>
    simp only [core.option.Option.Insts.CoreOpsTry_traitTry.branch]
    have hv := ho v rfl
    step*
    intro t ht
    cases ht
    scalar_tac

set_option linter.unusedTactic false in
set_option linter.unreachableTactic false in
/-- `decimal` returns on any bytes, and the exponent of a number it reads is far from the ends of
`i64`. -/
theorem decimal_spec (s : Slice Std.U8) (hs : s.length < 2 ^ 62) :
    decimal s ⦃ r => ∀ t, r = some t →
      -(2 ^ 62 + 10000009 : Int) ≤ t.2.2.val ∧ t.2.2.val ≤ 2 ^ 62 + 10000009 ⦄ := by
  unfold decimal
  dsimp only
  repeat' (first
    | exact exp_tail s _ _ _ _ (by scalar_tac) hs ⟨by scalar_tac, by scalar_tac⟩
    | split
    | step*)
  all_goals (simp only [WP.spec_ok]; intro t ht; cases ht; try scalar_tac)

set_option linter.unusedTactic false in
set_option linter.unreachableTactic false in
/-- The loop that looks for the end of the number from the end of the size: it ends on a place that
is not past the end. -/
theorem sep_loop_spec (s : Slice Std.U8) (sep i : Std.Usize) (h : sep.val ≤ s.length ∧ i.val ≤ s.length) :
    parse_size_loop0 s sep i ⦃ r => r.val ≤ s.length ⦄ := by
  unfold parse_size_loop0
  apply loop.spec_decr_nat (fun (q : Std.Usize × Std.Usize) => q.2.val)
    (fun (q : Std.Usize × Std.Usize) => q.1.val ≤ s.length ∧ q.2.val ≤ s.length)
    (fun (r : Std.Usize) => r.val ≤ s.length)
  · rintro ⟨sep1, i1⟩ ⟨h1, h2⟩
    simp only at h1 h2 ⊢
    unfold parse_size_loop0.body
    step*
    all_goals (try scalar_tac)
    all_goals (have hd := b_post.mp ‹_›; try scalar_tac)
  · exact h

/-- `i64::MAX` keeps its value as a `u128`. -/
@[scalar_tac_simps, simp]
theorem hcast_max_u128 : (IScalar.hcast UScalarTy.U128 core.num.I64.MAX).val = 2 ^ 63 - 1 := by
  have hm : (core.num.I64.MAX).val = 2 ^ 63 - 1 := by rfl
  rw [IScalar.hcast_val_eq, hm]; rfl

set_option linter.unusedTactic false in
set_option linter.unreachableTactic false in
/-- The loops that scale the size by the power of ten: they end, whatever the exponent is, as long as
it is not the least `i64`. -/
theorem scale_loop_spec (exp : Std.I64) (v : Std.U128) (k : Std.I64) (h : 0 ≤ k.val) :
    parse_size_loop1 exp v k ⦃ _ => True ⦄ := by
  unfold parse_size_loop1
  apply loop.spec_decr_nat (fun (q : Std.U128 × Std.I64) => q.2.val.toNat)
    (fun (q : Std.U128 × Std.I64) => 0 ≤ q.2.val)
    (fun (_ : Std.U128) => True)
  · rintro ⟨v1, k1⟩ h1
    simp only at h1 ⊢
    unfold parse_size_loop1.body
    step*
    all_goals scalar_tac
  · exact h


attribute [local step] sep_loop_spec decimal_spec unit_shift_spec scale_loop_spec

/-- A number of `u128` below 2^63 keeps its value as an `i64`. -/
theorem hcast_u128_i64 (v : Std.U128) (h : v.val < 2 ^ 63) :
    (UScalar.hcast IScalarTy.I64 v).val = v.val := by
  have hb : (((2 ^ IScalarTy.I64.numBits : Nat)) : Int) = 2 ^ 64 := by rfl
  rw [UScalar.hcast_val_eq, Int.bmod_def, hb]
  split_ifs <;> omega

set_option linter.unusedTactic false in
set_option linter.unreachableTactic false in
/-- The end of `parse_size`: the unit is read, and the size is scaled by the power of ten. -/
theorem parse_scale (s : Slice Std.U8) (unit : Std.Usize) (m : Std.U64) (exp : Std.I64)
    (hu : unit.val ≤ s.length) (hexp : -(2 ^ 62 + 10000009 : Int) ≤ exp.val ∧ exp.val ≤ 2 ^ 62 + 10000009) :
    (do
      let s2 ← core.slice.index.SliceIndexRangeFromUsizeSlice.index { start := unit } s
      let o1 ← unit_shift s2
      match o1 with
      | none => ok (core.result.Result.Err (SizeError.Suffix unit))
      | some n => do
        let i3 ← lift (UScalar.cast UScalarTy.U128 m)
        let v ← i3 <<< n
        let k ← if exp < 0#i64 then -.exp else ok exp
        let v1 ← parse_size_loop1 exp v k
        let i4 ← lift (IScalar.hcast UScalarTy.U128 core.num.I64.MAX)
        if v1 ≥ i4 then ok (core.result.Result.Err SizeError.Invalid)
        else do
          let i5 ← lift (UScalar.hcast IScalarTy.I64 v1)
          ok (core.result.Result.Ok i5)) ⦃ r =>
      ∀ n, r = core.result.Result.Ok n → 0 ≤ n.val ∧ n.val < MaxI64 ⦄ := by
  have hmin : (I64.min : Int) = -(2 ^ 63) := by simp [I64.min_def, I64.numBits]
  step*
  split
  · step*
    all_goals
      intro r hr; cases hr
      have hv : v1.val < 2 ^ 63 - 1 := by scalar_tac
      rw [i5_post, hcast_u128_i64 v1 (by omega)]
      unfold MaxI64; omega
  · step*
    all_goals
      intro r hr; cases hr
      have hv : v1.val < 2 ^ 63 - 1 := by scalar_tac
      rw [i5_post, hcast_u128_i64 v1 (by omega)]
      unfold MaxI64; omega

attribute [local step] parse_scale

set_option linter.unusedTactic false in
set_option linter.unreachableTactic false in
/-- Proof of `TheSizeIsBelowTheTop`: the answer is the `u128` value after the scaling, which was checked to be below `i64::MAX`. -/
theorem parse_size_post (s : Slice Std.U8) (short : Short s.val) : parse_size s ⦃ r =>
    ∀ n, r = core.result.Result.Ok n → 0 ≤ n.val ∧ n.val < MaxI64 ⦄ := by
  -- the place of the number's end is found, the number read, the unit read, and the size scaled
  unfold parse_size
  have hs : s.length < 2 ^ 62 := short.1
  dsimp only
  step*
  split
  all_goals
    step*
    rcases d with ⟨neg, m, exp⟩
    have hexp := o_post _ ‹o = some (neg, m, exp)›
    dsimp only at hexp
    show WP.spec (Std.bind _ _) _
    split
    all_goals simp only [← bind_tc_eq, bind_tc_ok]
    all_goals split
    all_goals first
      | exact parse_scale s _ m exp (by scalar_tac) hexp
      | (simp only [WP.spec_ok]; intro n hn; cases hn)

end LimitCore
