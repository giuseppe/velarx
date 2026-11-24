-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of `NumberOfBlanksIsZero`,
-- `NumberOfOctalDigitsIsTheirValue` and `NumberNeverFails` (Spec.lean):
-- what `number` of crates/tarsplit-header does with an octal field, and
-- that it cannot panic on a base-256 one.
--
-- The argument follows the Rust, `number` then `octal`, then its loops:
--   1. `number` reads the first byte, if there is one; with the marker
--      bit it calls `base256` (only shown not to panic: `base256_total`),
--      without it, or for an empty field, `cstr` then `octal` of what it
--      returns (`octal_of_cstr_spec`).
--   2. `octal` skips the spaces in front (`octal_loop0_spec`), drops those at
--      the end (`octal_loop1_spec`), and reads what is between with a loop
--      over the bytes (`octal_loop2_spec`): the value is shifted by 3 and
--      the low 3 bits of each digit put in (`shift_in_digit`).  Up to 21
--      digits the value stays below 2^63, so no shift loses a bit.
--   3. `octal_spec` puts these together, `number_spec` adds `cstr`; the
--      three claims are read off `number_spec`.
--
-- Read before this file: Cstr.lean and the statements in Spec.lean.
--
-- Notation: as in Cstr.lean.  `x &&& y` and `x ||| y` are the bitwise "and"
-- and "or"; `x <<< n` and `x >>> n` shift the bits of `x` by `n` places;
-- `octal_loop2 ⟨s, 0⟩ ...` is the loop over the bytes of `s` from the first
-- (`⟨s, 0⟩` is the iterator of `s` at its start).
import TarsplitHeader.Cstr

open Aeneas Aeneas.Std Result velarx_tarsplit_header

namespace TarsplitHeader

/-- `RangeInclusive<u8>::contains` (Models.lean) on a range that is not exhausted. -/
theorem contains_u8 (r : core.ops.range.RangeInclusive Std.U8) (x : Std.U8)
    (fresh : r.exhausted = false) :
    core.ops.range.RangeInclusive.contains core.cmp.PartialOrdU8 core.cmp.PartialOrdU8
      core.cmp.PartialOrdU8 r x = ok (decide (r.start.val ≤ x.val ∧ x.val ≤ r.end.val)) := by
  simp only [core.ops.range.RangeInclusive.contains, fresh]
  by_cases hs : r.start.val ≤ x.val <;> simp [hs, core.cmp.impls.PartialOrdU8.le]

/-- What one more octal digit `b` does to the number read so far, in the bits:
the number is shifted by 3 and the low 3 bits of the digit are put in. -/
theorem shift_in_digit (value i1 i3 : Std.U64) (b i2 : Std.U8)
    (small : value.val < 2 ^ 61) (digit : 48 ≤ b.val ∧ b.val ≤ 55)
    (shifted : i1.val = value.val <<< 3 % U64.size) (low : i2 = b &&& 7#u8)
    (wide : i3.val = i2.val) :
    (i1 ||| i3).val = 8 * value.val + (b.val - 48) := by
  have hd : i2.val = b.val - 48 := by
    subst low
    simp only [UScalar.val_and]
    rw [show (7#u8).val = 2 ^ 3 - 1 from rfl, Nat.and_two_pow_sub_one_eq_mod]
    omega
  have h1 : i1.val = 8 * value.val := by
    rw [shifted, Nat.shiftLeft_eq]
    simp [U64.size, U64.numBits]
    omega
  have h3 : i3.val < 2 ^ 3 := by omega
  rw [UScalar.val_or, show i1.val = value.val <<< 3 by rw [h1, Nat.shiftLeft_eq]; omega,
    ← Nat.shiftLeft_add_eq_or_of_lt h3, Nat.shiftLeft_eq]
  omega

/-- One more digit at the end of the digits read is one more step of the value. -/
theorem octalValue_snoc (ds : List Std.U8) (d : Std.U8) :
    octalValue (ds ++ [d]) = 8 * octalValue ds + (d.val - 48) := by
  simp [octalValue]

/-- The loop of `octal` that reads the digits: with octal digits only, nothing
is wrong; and either no overflow was seen and the number is the value of the
digits, or one was and the value of the digits is above 64 bits. -/
@[step]
theorem octal_loop2_spec (s : Slice Std.U8) :
    octal_loop2 ⟨s, 0⟩ 0#u64 false false ⦃ r =>
      (∀ b ∈ s.val, 48 ≤ b.val ∧ b.val ≤ 55) →
        r.2.1 = false ∧ (r.2.2 = false → r.1.val = octalValue s.val) ∧
        (r.2.2 = true → 2 ^ 64 ≤ octalValue s.val) ⦄ := by
  unfold octal_loop2
  -- after `i` digits: nothing is wrong; the number is their value while no
  -- overflow was seen, and the value is above 64 bits once one was seen
  apply loop.spec_decr_nat (fun p => s.length - p.1.i)
    (fun p => p.1.slice = s ∧ p.1.i ≤ s.length ∧
      ((∀ b ∈ s.val, 48 ≤ b.val ∧ b.val ≤ 55) →
        p.2.2.1 = false ∧ (p.2.2.2 = false → p.2.1.val = octalValue (s.val.take p.1.i)) ∧
        (p.2.2.2 = true → 2 ^ 64 ≤ octalValue (s.val.take p.1.i))))
  · rintro ⟨it, value, invalid, overflow⟩ ⟨hs, hi, hall⟩
    simp only at hs hi hall ⊢
    unfold octal_loop2.body
    simp only [core.slice.iter.IteratorSliceIter.next, Slice.len]
    split
    · simp only [Std.bind_ok]
      rename_i inside
      step as ⟨ ri, hs1, hs2, hex ⟩
      rw [contains_u8 ri _ hex]
      simp only [Std.bind_ok]
      step*
      simp only [lift, Std.bind_ok, Std.WP.spec_ok]
      subst hs
      have hlt : it.i < it.slice.val.length := by scalar_tac
      have hlt' : it.i < it.slice.length := by scalar_tac
      refine ⟨rfl, hlt', ?_, by omega⟩
      intro hdigits
      obtain ⟨hvalid, hexact, hover⟩ := hall hdigits
      have hdigit := hdigits _ (List.getElem_mem hlt)
      have wide : (core.convert.num.FromU64U8.from i2).val = i2.val := by scalar_tac
      -- the digit read is one more step of the value of the digits
      have step_value : octalValue (List.take (it.i + 1) it.slice.val) =
          8 * octalValue (List.take it.i it.slice.val) + (it.slice[it.i].val - 48) := by
        rw [List.take_add_one, List.getElem?_eq_getElem hlt]
        exact octalValue_snoc _ _
      -- `value >>> 61` is not 0 exactly when the value is 2^61 or more
      have top : i.val = value.val / 2 ^ 61 := by rw [i_post, Nat.shiftRight_eq_div_pow]
      refine ⟨?_, ?_, ?_⟩
      · simp [hs1, hs2, hvalid]
        omega
      · -- no overflow seen: the value was below 2^61 and the shift lost nothing
        intro none_seen
        have ⟨old, fresh⟩ := Bool.or_eq_false_iff.mp none_seen
        have small : value.val < 2 ^ 61 := by
          by_contra big
          have : i != 0#u64 := by
            simp only [bne_iff_ne, ne_eq]
            intro h0
            rw [h0] at top
            have : (0#u64).val = 0 := rfl
            omega
          simp_all
        rw [shift_in_digit value i1 _ _ i2 small hdigit i1_post (UScalar.eq_of_val_eq i2_post) wide,
          step_value, hexact old]
        rfl
      · -- an overflow seen: now, or before; the value of the digits is above 64 bits
        intro seen
        by_cases old : overflow = true
        · have := hover old
          omega
        · have fresh : (i != 0#u64) = true := by simpa [old] using seen
          have big : 2 ^ 61 ≤ value.val := by
            have : i.val ≠ 0 := by
              intro h0
              have : i = 0#u64 := UScalar.eq_of_val_eq h0
              simp [this] at fresh
            omega
          have := hexact (by simpa using old)
          rw [step_value]
          omega
    · simp
      subst hs
      have : it.slice.val.length ≤ it.i := by scalar_tac
      intro hdigits
      obtain ⟨hvalid, hexact, hover⟩ := hall hdigits
      rw [List.take_of_length_le this] at hexact hover
      exact ⟨hvalid, hexact, hover⟩
  · simp [octalValue]

/-- The loop of `octal` that skips the spaces in front of the number ends at
the first byte that is not a space. -/
@[step]
theorem octal_loop0_spec (field : Slice Std.U8) :
    octal_loop0 field 0#usize ⦃ r => r.val ≤ field.length ∧
      field.val.take r.val = field.val.takeWhile (fun b => decide (b = 32#u8)) ⦄ :=
  scan_spec _ field _ fun x => by
    simp only [octal_loop0.body, decide_eq_true_eq]

/-- The loop of `octal` that drops the spaces at the end of the number goes
back over spaces only, and no further than `start`. -/
@[step]
theorem octal_loop1_spec (field : Slice Std.U8) (start stop : Std.Usize)
    (inside : stop.val ≤ field.length) (le : start.val ≤ stop.val) :
    octal_loop1 field start stop ⦃ r => start.val ≤ r.val ∧ r.val ≤ stop.val ∧
      ∀ j, r.val ≤ j → j < stop.val → field.val[j]? = some 32#u8 ⦄ := by
  unfold octal_loop1
  -- from `e` to `stop`, the bytes are spaces; `e` goes down to `start` at most
  apply loop.spec_decr_nat (fun e => e.val)
    (fun e => start.val ≤ e.val ∧ e.val ≤ stop.val ∧
      ∀ j, e.val ≤ j → j < stop.val → field.val[j]? = some 32#u8)
  · intro e ⟨hs, he, hspaces⟩
    unfold octal_loop1.body
    split
    · rename_i above
      step as ⟨ prev, hprev ⟩
      step as ⟨ b, hb ⟩
      split
      · -- a space: one step back
        rename_i space
        simp only [Std.WP.spec_ok]
        refine ⟨by scalar_tac, by scalar_tac, ?_, by scalar_tac⟩
        intro j hj hjs
        rcases Nat.eq_or_lt_of_le hj with rfl | hj
        · rw [List.getElem?_eq_getElem (by scalar_tac)]
          exact congrArg some (hb.symm.trans space)
        · exact hspaces j (by omega) hjs
      · -- not a space: stop
        simp only [Std.WP.spec_ok]
        exact ⟨hs, he, hspaces⟩
    · simp only [Std.WP.spec_ok]
      exact ⟨hs, he, hspaces⟩
  · exact ⟨le, le_refl _, fun j hj hjs => by omega⟩

/-- `octal`: a field of spaces is 0; a field of octal digits is their value,
or an overflow when the value does not fit in 64 bits. -/
theorem octal_spec (s : Slice Std.U8) :
    octal s ⦃ r =>
      ((∀ b ∈ s.val, b = 32#u8) → r = core.result.Result.Ok 0#u64) ∧
      ((∀ b ∈ s.val, 48 ≤ b.val ∧ b.val ≤ 55) →
        if octalValue s.val < 2 ^ 64 then
          ∃ n : Std.U64, r = core.result.Result.Ok n ∧ n.val = octalValue s.val
        else r = core.result.Result.Err NumError.Overflow) ⦄ := by
  unfold octal
  -- the spaces in front are skipped, those at the end are dropped, the
  -- digits are what is between, and the loop reads them
  step as ⟨ start, hstart, hskipped ⟩
  step as ⟨ stop, hstop, hstop_le, hspaces ⟩
  step as ⟨ digits, hdigits_val, hdigits_len ⟩
  step as ⟨ iter, hiter, hfirst ⟩
  obtain rfl : iter = ⟨digits, 0⟩ := by cases iter; simp_all
  step as ⟨ value, invalid, overflow, hloop ⟩
  -- a field of spaces leaves no digit
  have blank : (∀ b ∈ s.val, b = 32#u8) → value.val = 0 ∧ invalid = false ∧ overflow = false := by
    intro spaces
    have all : s.val.takeWhile (fun b => decide (b = 32#u8)) = s.val := by
      rw [← take_is_takeWhile _ _ s.val.length _ (by simp)]
      · simp
      · intro b hb
        simpa using spaces b (List.mem_of_mem_take hb)
    have hstart_end : start.val = s.length := by
      have := congrArg List.length hskipped
      rw [all] at this
      scalar_tac
    have empty : digits.val = [] := by
      apply List.eq_nil_of_length_eq_zero
      scalar_tac
    obtain ⟨hvalid, hexact, hover⟩ := hloop (by simp [empty])
    simp only [empty, octalValue, List.foldl_nil] at hexact hover
    have no_overflow : overflow = false := by
      by_contra seen
      have := hover (by simpa using seen)
      omega
    exact ⟨hexact no_overflow, hvalid, no_overflow⟩
  -- a field of octal digits is all digits
  have digits_are_s : (∀ b ∈ s.val, 48 ≤ b.val ∧ b.val ≤ 55) → digits.val = s.val := by
    intro digit
    have not_space : s.val.takeWhile (fun b => decide (b = 32#u8)) = [] := by
      cases hl : s.val with
      | nil => rfl
      | cons first _ =>
        have := digit first (by simp [hl])
        rw [List.takeWhile_cons_of_neg]
        simp only [decide_eq_true_eq]
        intro heq
        rw [heq] at this
        exact absurd this.1 (by decide)
    have from_start : start.val = 0 := by
      rw [not_space] at hskipped
      rcases List.take_eq_nil_iff.mp hskipped with h | h
      · exact h
      · simp [h] at hstart; omega
    have to_end : stop.val = s.length := by
      by_contra short_of_end
      have := hspaces (s.length - 1) (by scalar_tac) (by scalar_tac)
      rw [List.getElem?_eq_getElem (by scalar_tac)] at this
      have := digit _ (List.getElem_mem (show s.length - 1 < s.val.length by scalar_tac))
      simp_all
    rw [hdigits_val, from_start, to_end]
    simp [List.slice]
  -- the end of `octal`: an invalid field, an overflow, or the value
  by_cases hi : invalid = true
  · simp only [hi, ↓reduceIte, Std.WP.spec_ok]
    exact ⟨fun spaces => by simpa [hi] using (blank spaces).2.1,
      fun digit => by simpa [hi, digits_are_s digit] using (hloop (by rwa [digits_are_s digit])).1⟩
  by_cases ho : overflow = true
  · simp only [hi, ho, Bool.false_eq_true, ↓reduceIte, Std.WP.spec_ok]
    refine ⟨fun spaces => by simpa [ho] using (blank spaces).2.2, fun digit => ?_⟩
    have := (hloop (by rwa [digits_are_s digit])).2.2 ho
    rw [digits_are_s digit] at this
    have no_fit : ¬ octalValue s.val < 2 ^ 64 := not_lt.mpr this
    simp only [no_fit, ↓reduceIte]
  · simp only [hi, ho, Bool.false_eq_true, ↓reduceIte, Std.WP.spec_ok]
    refine ⟨fun spaces => congrArg _ (UScalar.eq_of_val_eq (by simpa using (blank spaces).1)),
      fun digit => ?_⟩
    have := (hloop (by rwa [digits_are_s digit])).2.1 (by simpa using ho)
    rw [digits_are_s digit] at this
    have fits : octalValue s.val < 2 ^ 64 := by
      rw [← this]
      have := value.hBounds
      simpa [UScalarTy.numBits] using this
    simp only [fits, ↓reduceIte]
    exact ⟨value, rfl, this⟩

/-- The loop of `base256` goes over the bytes after the first: only shifts
by 8 (less than the 64 bits of the number), so nothing can panic. -/
@[step]
theorem base256_loop_total (s : Slice Std.U8) (value : Std.U64) (overflow : Bool) :
    base256_loop ⟨s, 0⟩ value overflow ⦃ _ => True ⦄ := by
  unfold base256_loop
  -- the iterator stays on the slice and goes one byte on at each turn
  apply loop.spec_decr_nat (fun p => s.length - p.1.i)
    (fun p => p.1.slice = s ∧ p.1.i ≤ s.length)
  · rintro ⟨it, value, overflow⟩ ⟨hs, hi⟩
    simp only at hs hi ⊢
    unfold base256_loop.body
    simp only [core.slice.iter.IteratorSliceIter.next, Slice.len]
    split
    · simp only [Std.bind_ok]
      step*
      simp only [lift, Std.bind_ok, Std.WP.spec_ok]
      refine ⟨hs, ?_⟩
      scalar_tac
    · simp
  · simp

/-- `base256` returns for any field that has a first byte. -/
theorem base256_total (field : Slice Std.U8) (nonempty : 0 < field.length) :
    base256 field ⦃ _ => True ⦄ := by
  unfold base256
  step*
  simp only [lift, Std.bind_ok]
  step as ⟨ rest, hrest ⟩
  step as ⟨ iter, hiter, hfirst ⟩
  obtain rfl : iter = ⟨rest, 0⟩ := by cases iter; simp_all
  step as ⟨ value, overflow ⟩
  step*

/-- A byte below 128 has no marker bit. -/
theorem no_marker_bit (first : Std.U8) (low : first.val < 128) : (first &&& 128#u8).val = 0 := by
  rw [UScalar.val_and, show (128#u8).val = 2 ^ 7 from rfl]
  apply Nat.eq_of_testBit_eq
  intro i
  simp only [Nat.testBit_and, Nat.testBit_two_pow, Nat.zero_testBit]
  by_cases hi : 7 = i
  · subst hi
    simp [Nat.testBit_eq_false_of_lt (show first.val < 2 ^ 7 by omega)]
  · simp [hi]

/-- What `number` returns for a field, the two claims of Spec.lean: a field
of spaces and NULs is 0; octal digits followed by a NUL are their value, or
an overflow when it does not fit in 64 bits. -/
def NumberClaims (field : Slice Std.U8) (r : core.result.Result Std.U64 NumError) : Prop :=
  ((∀ b ∈ field.val, b = 0#u8 ∨ b = 32#u8) → r = core.result.Result.Ok 0#u64) ∧
  (∀ ds rest, field.val = ds ++ 0#u8 :: rest → (∀ d ∈ ds, 48 ≤ d.val ∧ d.val ≤ 55) →
    if octalValue ds < 2 ^ 64 then
      ∃ n : Std.U64, r = core.result.Result.Ok n ∧ n.val = octalValue ds
    else r = core.result.Result.Err NumError.Overflow)

/-- The octal branch of `number`, `octal` of what `cstr` returns, makes the
claims for any field. -/
theorem octal_of_cstr_spec (field : Slice Std.U8) :
    (do let s ← cstr field; octal s) ⦃ r => NumberClaims field r ⦄ := by
  step with cstr_is_the_prefix field as ⟨ text, htext ⟩
  refine Std.WP.spec_mono (octal_spec text)
    fun r hr => ⟨fun blanks => ?_, fun ds rest hfield digits => ?_⟩
  · -- the text is spaces: the NULs end it
    apply hr.1
    intro b hb
    rw [htext] at hb
    have ⟨hmem, hnonzero⟩ := mem_takeWhile _ _ _ hb
    rcases blanks b hmem with rfl | rfl
    · simp at hnonzero
    · rfl
  · -- the text is the digits: they are not NUL and a NUL follows
    have same : text.val = ds := by
      rw [htext, hfield]
      refine (take_is_takeWhile _ _ ds.length ?_ ?_).symm.trans (List.take_left' rfl)
      · intro b hb
        rw [List.take_left' rfl] at hb
        have := (digits b hb).1
        simp only [bne_iff_ne, ne_eq]
        intro hz
        rw [hz] at this
        exact absurd this (by decide)
      · intro b hb
        simp at hb
        simp [← hb]
    simpa [same] using hr.2 (by simpa [same] using digits)

/-- `number` makes the claims for any field: an empty one or one without the
marker bit is read by the octal branch; with the marker bit, base 256, the
field is neither blank nor digits. -/
theorem number_spec (field : Slice Std.U8) : number field ⦃ r => NumberClaims field r ⦄ := by
  unfold number
  step as ⟨ empty, hempty ⟩
  split
  · -- an empty field: octal
    exact octal_of_cstr_spec field
  rename_i nonempty
  step as ⟨ first, hfirst ⟩
  step as ⟨ marker, hmarker ⟩
  split
  · -- the marker bit is set: base 256, which does not panic; and the field
    -- is neither blank nor digits, whose first byte is below 128
    rename_i marked
    refine Std.WP.spec_mono (base256_total field (by simp only [hempty] at nonempty; scalar_tac))
      fun r _ => ⟨fun blanks => ?_, fun ds rest hfield digits => ?_⟩
    all_goals
      apply absurd marked
      suffices low : first.val < 128 by
        have : marker = 0#u8 := UScalar.eq_of_val_eq (by rw [hmarker]; exact no_marker_bit first low)
        simp [this]
    · rcases blanks first (by simp [hfirst]) with rfl | rfl <;> simp
    · cases ds with
      | nil => simp [hfirst, hfield]
      | cons d t =>
        have := digits d (by simp)
        simp [hfirst, hfield]
        omega
  · -- no marker bit: octal
    exact octal_of_cstr_spec field

/-- A field of spaces and NULs is read as 0, as Spec.lean says. -/
theorem number_of_blanks_is_zero : NumberOfBlanksIsZero :=
  fun field blanks => Std.WP.spec_mono (number_spec field) fun _ h => h.1 blanks

/-- Octal digits are read as their value, as Spec.lean says. -/
theorem number_of_octal_digits_is_their_value : NumberOfOctalDigitsIsTheirValue :=
  fun field ds rest hfield digits =>
    Std.WP.spec_mono (number_spec field) fun _ h => h.2 ds rest hfield digits

/-- `number` returns for any field, as Spec.lean says. -/
theorem number_never_fails : NumberNeverFails :=
  fun field => Std.WP.spec_mono (number_spec field) fun _ _ => trivial

end TarsplitHeader
