-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of `DecimalNeverFails`,
-- `PaxTimeNeverFails` and `PaxRecordStaysInside` (Spec.lean): `decimal`,
-- `pax_time` and `pax_record` of crates/tarsplit-header, which read the
-- records of a PAX extended header, never panic, and `pax_record` gives
-- ranges that are inside the payload.
--
-- Why it is needed: the PAX payload of a layer is read before the layer
-- can be checked, so the arithmetic on its bytes (the length written in
-- decimal, the places of the key and the value, the nanoseconds) must hold
-- for any bytes.  The reader of crates/tarsplit slices the payload with
-- what `pax_record` returns; that these slices are inside it is what is
-- proved here.
--
-- The argument follows the Rust, loop by loop:
--   1. `decimal` shifts one digit in at a time and checks, before it
--      multiplies, that the next digit still fits (`decimal_loop_total`).
--   2. The loops that look for a byte (the space, the dot, the `=`) end
--      between where they start and the limit, on the byte if they find
--      one, with none of it before (`find_spec`).
--   3. `pax_time` adds each digit of the fraction times a tenth of the one
--      before: the sum stays below 2 * 10^9 for any byte, and below 10^9
--      when every byte is a digit, so the subtraction from a second of a
--      negative time cannot underflow (`pax_time_loop1_spec`).  Its seconds
--      are at most 2^63 - 1, so the negation and the one taken away fit.
--   4. `pax_record` reads the length with `decimal`, refuses it when it is
--      past the payload, and looks for the `=` between the key and the end
--      of the record; each index it takes is below the length.
--
-- Read before this file: the statements in Spec.lean and Number.lean (the
-- shape of a loop proof, and `contains_u8`, the test of a digit).
--
-- Notation: as in Cstr.lean and Number.lean.  `step as ⟨ x, hx ⟩` goes through a line and
-- names its result `x` and what is known of it `hx`; `simp only
-- [Std.WP.spec_ok]` closes the goal of a function that returned an error:
-- nothing is claimed of an error.  `b &&& 15` is the low 4 bits of the
-- byte `b`.
import TarsplitHeader.Number

open Aeneas Aeneas.Std Result velarx_tarsplit_header

namespace TarsplitHeader

/-- The low 4 bits of a byte are its rest modulo 16: for an ASCII digit,
the value of the digit. -/
theorem low_nibble (b : Std.U8) : (b &&& 15#u8).val = b.val % 16 := by
  rw [UScalar.val_and, show (15#u8).val = 2 ^ 4 - 1 from rfl, Nat.and_two_pow_sub_one_eq_mod]

/-- `is_digit` tests that the byte is between `'0'` and `'9'`. -/
@[step]
theorem is_digit_spec (b : Std.U8) :
    is_digit b ⦃ r => r = decide (48 ≤ b.val ∧ b.val ≤ 57) ⦄ := by
  unfold is_digit
  step as ⟨ ri, hstart, hend, hfresh ⟩
  rw [contains_u8 ri b hfresh]
  simp [hstart, hend]

/-- The loop of `decimal` returns for any bytes: the digit is at most 15, and
the number is only multiplied by 10 when it is at most `(2^64 - 1 - digit) / 10`,
so `10 * number + digit` fits. -/
@[step]
theorem decimal_loop_total (s : Slice Std.U8) (it : core.slice.iter.Iter Std.U8) (value : Std.U64)
    (invalid overflow : Bool) (hs : it.slice = s) (hi : it.i ≤ s.length) :
    decimal_loop it value invalid overflow ⦃ _ => True ⦄ := by
  unfold decimal_loop
  apply loop.spec_decr_nat (fun p => s.length - p.1.i)
    (fun p => p.1.slice = s ∧ p.1.i ≤ s.length)
  · rintro ⟨it, value, invalid, overflow⟩ ⟨hs, hi⟩
    simp only at hs hi ⊢
    unfold decimal_loop.body
    simp only [core.slice.iter.IteratorSliceIter.next, Slice.len]
    split
    · simp only [Std.bind_ok]
      step as ⟨ digit, hdigit ⟩
      subst hdigit
      -- the low 4 bits of the byte are at most 15
      step as ⟨ low, hlow ⟩
      have low_le : low.val ≤ 15 := by rw [hlow, low_nibble]; omega
      simp only [lift, Std.bind_ok]
      have wide : (core.convert.num.FromU64U8.from low).val = low.val := by scalar_tac
      have top : core.num.U64.MAX.val = 2 ^ 64 - 1 := by decide
      step*
    · simp
  · exact ⟨hs, hi⟩

/-- A loop that steps over the bytes of `data` from `start` up to `limit`
while they are not `c` (written out here, as Aeneas wrote the loops that look
for the space, the dot and the `=`) ends between `start` and `limit`, on a `c`
if it stopped before `limit`, with no `c` before. -/
theorem find_spec (c : Std.U8) (data : Slice Std.U8) (limit start : Std.Usize)
    (inside : limit.val ≤ data.length) (le : start.val ≤ limit.val)
    (body : Std.Usize → Result (ControlFlow Std.Usize Std.Usize))
    (is_find : ∀ x, body x =
      if x < limit then do
        let b ← Slice.index_usize data x
        if b != c then do
          let x1 ← x + 1#usize
          ok (ControlFlow.cont x1)
        else ok (ControlFlow.done x)
      else ok (ControlFlow.done x)) :
    loop body start ⦃ r => start.val ≤ r.val ∧ r.val ≤ limit.val ∧
      (r.val < limit.val → data.val[r.val]? = some c) ∧
      (∀ j, start.val ≤ j → j < r.val → data.val[j]? ≠ some c) ⦄ := by
  apply loop.spec_decr_nat (fun e => limit.val - e.val)
    (fun e => start.val ≤ e.val ∧ e.val ≤ limit.val ∧
      ∀ j, start.val ≤ j → j < e.val → data.val[j]? ≠ some c)
  · intro x ⟨hs, hx, before⟩
    rw [is_find]
    split
    · rename_i inside_limit
      have hlt : x.val < data.val.length := by scalar_tac
      step as ⟨ b, hb ⟩
      split
      · rename_i differs
        step as ⟨ x1, hx1 ⟩
        refine ⟨by scalar_tac, by scalar_tac, ?_, by scalar_tac⟩
        intro j hj hjx
        by_cases old : j < x.val
        · exact before j hj old
        · rw [show j = x.val by omega, List.getElem?_eq_getElem hlt]
          simpa [← hb] using differs
      · rename_i found
        simp only [Std.WP.spec_ok]
        refine ⟨hs, hx, fun _ => ?_, before⟩
        rw [List.getElem?_eq_getElem hlt]
        simp only [bne_iff_ne, ne_eq, not_not] at found
        rw [← found, hb]
    · simp only [Std.WP.spec_ok]
      exact ⟨hs, hx, fun lt => by scalar_tac, before⟩
  · exact ⟨le_refl _, le, fun j hj hjs => by omega⟩

/-- The loop of `pax_time` that reads the fraction.  The nanoseconds are a sum
of digits (at most 15) times the scale, which starts at 10^8 and is divided
by 10 at each digit, so: for any bytes the sum stays below 2 * 10^9 (it fits
in 32 bits, and so does the product); and when every byte is a digit, it stays
below 10^9, which is what a negative time subtracts it from. -/
@[step]
theorem pax_time_loop1_spec (s : Slice Std.U8) (it : core.slice.iter.Iter Std.U8)
    (nanos scale : Std.U32) (invalid : Bool) (hs : it.slice = s) (hi : it.i ≤ s.length)
    (small : scale.val ≤ 10 ^ 8) (room : nanos.val + 20 * scale.val ≤ 2 * 10 ^ 9)
    (exact : invalid = false → nanos.val + 10 * scale.val ≤ 10 ^ 9 ∧
      (scale.val = 0 → nanos.val < 10 ^ 9)) :
    pax_time_loop1 it nanos scale invalid ⦃ r => r.2 = false → r.1.val < 10 ^ 9 ⦄ := by
  unfold pax_time_loop1
  apply loop.spec_decr_nat (fun p => s.length - p.1.i)
    (fun p => p.1.slice = s ∧ p.1.i ≤ s.length ∧ p.2.2.1.val ≤ 10 ^ 8 ∧
      p.2.1.val + 20 * p.2.2.1.val ≤ 2 * 10 ^ 9 ∧
      (p.2.2.2 = false → p.2.1.val + 10 * p.2.2.1.val ≤ 10 ^ 9 ∧
        (p.2.2.1.val = 0 → p.2.1.val < 10 ^ 9)))
  · rintro ⟨it, nanos, scale, invalid⟩ ⟨hs, hi, small, room, exact⟩
    simp only at hs hi small room exact ⊢
    unfold pax_time_loop1.body
    simp only [core.slice.iter.IteratorSliceIter.next, Slice.len]
    split
    · simp only [Std.bind_ok]
      step as ⟨ digit, hdigit ⟩
      subst hdigit
      -- the low 4 bits of the byte are at most 15, so the product fits
      step as ⟨ low, hlow ⟩
      have low_le : low.val ≤ 15 := by rw [hlow, low_nibble]; omega
      simp only [lift, Std.bind_ok]
      have wide : (core.convert.num.FromU32U8.from low).val = low.val := by scalar_tac
      have product : low.val * scale.val ≤ 15 * scale.val := Nat.mul_le_mul_right _ low_le
      step*
      rw [wide] at i2_post
      -- the bounds hold after one more byte; with a digit, the stronger one too
      refine ⟨hs, by scalar_tac, by omega, by omega, ?_, by scalar_tac⟩
      intro still_valid
      have ⟨valid, digit⟩ :
          invalid = false ∧ (48 ≤ it.slice[it.i].val ∧ it.slice[it.i].val ≤ 57) := by
        simpa using still_valid
      have low_digit : low.val ≤ 9 := by rw [hlow, low_nibble]; omega
      have product : low.val * scale.val ≤ 9 * scale.val := Nat.mul_le_mul_right _ low_digit
      have := exact valid
      omega
    · simp
      intro valid
      have := exact valid
      omega
  · exact ⟨hs, hi, small, room, exact⟩

/-- The loop of `pax_time` that looks for the dot stops at the end of the text
or on a dot. -/
@[step]
theorem pax_time_loop0_spec (text : Slice Std.U8) :
    pax_time_loop0 text 0#usize ⦃ r => r.val ≤ text.length ∧
      (r.val < text.length → text.val[r.val]? = some 46#u8) ⦄ := by
  unfold pax_time_loop0
  refine Std.WP.spec_mono (find_spec 46#u8 text (Slice.len text) 0#usize (by scalar_tac)
    (by scalar_tac) _ fun _ => rfl) fun r h => ⟨by scalar_tac, fun lt => h.2.2.1 (by scalar_tac)⟩

/-- `decimal` returns for any bytes: the loop does, and what is after it only
tests two flags. -/
@[step]
theorem decimal_total (digits : Slice Std.U8) : decimal digits ⦃ _ => True ⦄ := by
  unfold decimal
  step as ⟨ empty, hempty ⟩
  step as ⟨ iter, hiter, hfirst ⟩
  obtain rfl : iter = ⟨digits, 0⟩ := by cases iter; simp_all
  step*

/-- `decimal` never panics, as Spec.lean says. -/
theorem decimal_never_fails : DecimalNeverFails := decimal_total

/-- `pax_time` never panics and returns less than a second of nanoseconds, as
Spec.lean says. -/
theorem pax_time_never_fails : PaxTimeNeverFails := by
  intro value
  unfold pax_time
  step as ⟨ empty, hempty ⟩
  -- the minus sign, if there is one, is dropped: the text is no longer than the value
  refine Std.WP.spec_bind (Pₘ := fun r => r.2.length ≤ value.length) ?_ ?_
  · split
    · simp only [Std.WP.spec_ok]
      exact le_refl _
    · step as ⟨ first, hfirst ⟩
      split
      · step as ⟨ text, htext, hlen ⟩
        scalar_tac
      · simp only [Std.WP.spec_ok]
        exact le_refl _
  · rintro ⟨negative, text⟩ short
    -- the seconds are what is before the dot (`decimal` returns for any of it)
    step as ⟨ dot, hdot, hdot_at ⟩
    step as ⟨ digits, hdigits ⟩
    step as ⟨ secs ⟩
    cases secs with
    | Err e =>
      simp [core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
    | Ok secs =>
      -- more than 2^63 - 1 seconds are refused, so the cast keeps them
      simp only [core.result.Result.Insts.CoreOpsTry.branch, Std.bind_ok]
      step as ⟨ top, htop ⟩
      split
      · simp
      · rename_i fits
        step as ⟨ secs', hsecs' ⟩
        have in_range : 0 ≤ secs'.val ∧ secs'.val ≤ 2 ^ 63 - 1 := by
          have imax : core.num.I64.MAX.val = 2 ^ 63 - 1 := by decide
          have imaxv : IScalar.max IScalarTy.I64 = 2 ^ 63 - 1 := by
            rw [IScalar.max_def]; decide
          have top_val : top.val = 2 ^ 63 - 1 := by rw [htop]; decide
          have secs_le : secs.val ≤ 2 ^ 63 - 1 := by
            have : ¬ top.val < secs.val := fits
            omega
          have hv := (Std.WP.spec_ok _).mp (UScalar.hcast_inBounds_spec IScalarTy.I64 secs
            (by omega))
          rw [← hsecs'] at hv
          omega
        -- the fraction starts after the dot, if there is one, and is read by the loop
        refine Std.WP.spec_bind (Pₘ := fun f => f.val ≤ text.length) ?_ ?_
        · split
          · step as ⟨ next, hnext ⟩
            scalar_tac
          · simp only [Std.WP.spec_ok]
            exact hdot
        · intro fraction hfraction
          step as ⟨ digits', hdigits' ⟩
          step as ⟨ iter, hiter, hfirst ⟩
          obtain rfl : iter = ⟨digits', 0⟩ := by cases iter; simp_all
          step as ⟨ nanos, invalid, hnanos ⟩
          -- an invalid fraction is refused; a negative time is minus the seconds,
          -- less one when there are nanoseconds, which are then taken from a second
          split
          · simp
          · rename_i valid
            have nanos_below := hnanos (by simpa using valid)
            split
            · split
              · step as ⟨ neg ⟩
                simp
              · rename_i _ some_nanos
                step as ⟨ neg, hneg ⟩
                step as ⟨ before, hbefore ⟩
                step as ⟨ rest, hrest ⟩
                have : nanos.val ≠ 0 := fun zero => some_nanos (UScalar.eq_of_val_eq zero)
                omega
            · simp only [Std.WP.spec_ok]
              exact nanos_below

/-- The loop of `pax_record` that looks for the space stops at the end of the
payload or on a space. -/
@[step]
theorem pax_record_loop0_spec (data : Slice Std.U8) :
    pax_record_loop0 data 0#usize ⦃ r => r.val ≤ data.length ∧
      (r.val < data.length → data.val[r.val]? = some 32#u8) ⦄ := by
  unfold pax_record_loop0
  refine Std.WP.spec_mono (find_spec 32#u8 data (Slice.len data) 0#usize (by scalar_tac)
    (by scalar_tac) _ fun _ => rfl) fun r h => ⟨by scalar_tac, fun lt => h.2.2.1 (by scalar_tac)⟩

/-- The loop of `pax_record` that looks for the `=` goes from `eq` to the
newline that ends the record (`stop`) at most, and stops on an `=` if it
stopped before it, with no `=` before. -/
@[step]
theorem pax_record_loop1_spec (data : Slice Std.U8) (stop eq : Std.Usize)
    (inside : stop.val ≤ data.length) (le : eq.val ≤ stop.val) :
    pax_record_loop1 data stop eq ⦃ r => eq.val ≤ r.val ∧ r.val ≤ stop.val ∧
      (r.val < stop.val → data.val[r.val]? = some 61#u8) ∧
      (∀ j, eq.val ≤ j → j < r.val → data.val[j]? ≠ some 61#u8) ⦄ := by
  unfold pax_record_loop1
  exact find_spec 61#u8 data stop eq inside le _ fun _ => rfl

/-- A length in memory fits in 64 bits. -/
theorem usize_fits_u64 (x : Std.Usize) : x.val ≤ UScalar.max UScalarTy.U64 := by
  have := x.hBounds
  rcases System.Platform.numBits_eq with h | h <;> simp [UScalar.max_def, h] at this ⊢ <;> omega

/-- `pax_record` stays inside the payload, as Spec.lean says. -/
theorem pax_record_stays_inside : PaxRecordStaysInside := by
  intro data
  unfold pax_record
  step as ⟨ space, hspace, hspace_at ⟩
  split
  · simp
  · rename_i found
    -- the length is what is before the space, read by `decimal`
    step as ⟨ digits, hdigits ⟩
    step as ⟨ r ⟩
    cases r with
    | Err e => simp
    | Ok len =>
      -- a length written past the payload is refused; else it is a length in memory
      step as ⟨ wide, hwide ⟩
      have wide_val : wide.val = data.length := by
        have := (Std.WP.spec_ok _).mp (UScalar.cast_inBounds_spec UScalarTy.U64 data.len
          (usize_fits_u64 _))
        rw [← hwide] at this
        rw [this]
        simp
      split
      · simp only [Std.WP.spec_ok]
      · rename_i inside
        step as ⟨ len', hlen' ⟩
        have len'_val : len'.val = len.val := by
          have := (Std.WP.spec_ok _).mp (UScalar.cast_inBounds_spec UScalarTy.Usize len
            (by scalar_tac))
          rw [← hlen'] at this
          exact this
        have len_le : len.val ≤ data.length := by
          have : ¬ wide.val < len.val := inside
          omega
        step as ⟨ start, hstart ⟩
        split
        · simp only [Std.WP.spec_ok]
        · rename_i past_key
          -- a record longer than the digits and the space has a last byte: a newline
          step as ⟨ stop, hstop ⟩
          step as ⟨ newline, hnewline ⟩
          split
          · simp only [Std.WP.spec_ok]
          · rename_i is_newline
            -- the first `=` is looked for from the start of the key to the newline
            step as ⟨ eq, heq, heq_le, heq_at, heq_none ⟩
            split
            · simp only [Std.WP.spec_ok]
            · rename_i not_end
              step as ⟨ after_eq, hafter_eq ⟩
              have before_end : eq.val ≠ stop.val :=
                fun same => not_end (UScalar.eq_of_val_eq same)
              -- the byte before the key is the space the loop stopped on
              have space_inside : space.val < data.length := by
                have : space.val ≠ data.length :=
                  fun same => found (UScalar.eq_of_val_eq (by simpa using same))
                omega
              have after_space : data.val[start.val - 1]? = some 32#u8 := by
                rw [show start.val - 1 = space.val by omega]
                exact hspace_at space_inside
              -- the last byte of the record is the newline
              have last_byte : data.val[len'.val - 1]? = some 10#u8 := by
                have length : data.length = data.val.length := rfl
                rw [show len'.val - 1 = stop.val by omega, List.getElem?_eq_getElem (by omega)]
                simp only [bne_iff_ne, ne_eq, not_not] at is_newline
                rw [← is_newline, hnewline]
              have equals : data.val[eq.val]? = some 61#u8 := heq_at (by omega)
              refine ⟨by omega, by omega, last_byte, by omega, after_space, by omega, equals,
                heq_none, by omega, by omega, by omega⟩

end TarsplitHeader
