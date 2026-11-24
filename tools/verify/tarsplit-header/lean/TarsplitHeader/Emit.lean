-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of `PutOctalFitsOrIsRefused`,
-- `PutOctalWritesTheDigits`, `PutOctalIsReadBack`, `PutDecimalWritesTheDigits`,
-- `DecimalOfDigitsIsTheirValue` and `RecordLenCountsItself` (Spec.lean):
-- `put_octal`, `put_decimal` and `record_len` of crates/tarsplit-header/src/emit.rs,
-- which write the number fields and the PAX records of a canonical tar, and
-- that what they write is what `number` and `decimal` read.
--
-- Why it is needed: the canonical tar is the one tar a table of contents
-- describes, so a number that did not fit its field, or a record that did not
-- count its own length, would be a tar that is not the table's.  The reading
-- side is proved in Number.lean and Pax.lean; here is the writing side.
--
-- The argument follows the Rust, function by function, loop by loop:
--   1. `put_octal` writes the digits from the last to the first, one for each
--      three bits of the number; after `k` digits what is written spells the
--      number modulo 8^k and what is left is the number divided by 8^k
--      (`put_octal_loop_spec`).  The number fits exactly when nothing is left.
--   2. `put_decimal` finds the largest power of ten that is not above the
--      number (`put_decimal_loop0_spec`), then writes the digits from there
--      down, with the same invariant in base ten (`put_decimal_loop1_spec`).
--   3. `decimal` of digits is their value while the sum fits in 64 bits
--      (`decimal_loop_value`), as `octal` is in Number.lean.
--   4. `record_len` is the first try, `rest` and the digits of `rest`, or one
--      more; the digits of the first try are those of `rest` or one more, and
--      nothing smaller counts itself (`digits_of_first_try`, `fixpoint_ge`).
--
-- Read before this file: the statements in Spec.lean, then Number.lean (the
-- shape of a loop proof and `octalValue`) and Pax.lean (`decimal`).
--
-- Notation: as in Number.lean.  `step with lemma args as ⟨ x, hx ⟩` goes
-- through a line with the lemma, and names its result and what is known of it;
-- `ds ++ [0#u8]` is the list `ds` followed by a NUL; `l.val` is the list of the
-- bytes of a slice or of a vector; `Nat.log 10 n` is the largest `k` with
-- `10^k ≤ n`.
import TarsplitHeader.Pax
open Aeneas Aeneas.Std Result velarx_tarsplit_header
namespace TarsplitHeader

/-- The fold that reads digits, started from another number: that number shifted by
the places of the digits, then the value of the digits. -/
theorem octal_fold (a : Nat) (ds : List Std.U8) :
    ds.foldl (fun v d => 8 * v + (d.val - 48)) a =
      a * 8 ^ ds.length + ds.foldl (fun v d => 8 * v + (d.val - 48)) 0 := by
  induction ds generalizing a with
  | nil => simp
  | cons x xs ih =>
    simp only [List.foldl_cons, List.length_cons]
    rw [ih (8 * a + (x.val - 48)), ih (8 * 0 + (x.val - 48)), pow_succ]
    ring

/-- A digit in front of the digits read is its value times the place it ends up in. -/
theorem octalValue_cons (d : Std.U8) (ds : List Std.U8) :
    octalValue (d :: ds) = (d.val - 48) * 8 ^ ds.length + octalValue ds := by
  unfold octalValue
  simp only [List.foldl_cons, Nat.mul_zero, Nat.zero_add]
  rw [octal_fold]

/-- Octal digits spell a number below 8 to their count. -/
theorem octalValue_lt (ds : List Std.U8) (digits : ∀ d ∈ ds, 48 ≤ d.val ∧ d.val ≤ 55) :
    octalValue ds < 8 ^ ds.length := by
  induction ds with
  | nil => simp [octalValue]
  | cons x xs ih =>
    have hx := digits x (by simp)
    have := ih (fun d hd => digits d (by simp [hd]))
    rw [octalValue_cons, List.length_cons, pow_succ]
    have : (x.val - 48) * 8 ^ xs.length + octalValue xs < 8 * 8 ^ xs.length := by
      have : x.val - 48 ≤ 7 := by omega
      nlinarith
    linarith

/-- The loop of `put_octal`: from the end of the field, one digit for each three bits of the
number.  The digits written spell what the number has below 8 to their count, and what is left of
the number is the rest. -/
theorem put_octal_loop_spec (V : Nat) (field : Slice Std.U8) (rest : Std.U64) (pos : Std.Usize)
    (pre ds : List Std.U8)
    (shape : field.val = pre ++ ds ++ [0#u8]) (npre : pre.length = pos.val)
    (digits : ∀ d ∈ ds, 48 ≤ d.val ∧ d.val ≤ 55)
    (value : octalValue ds + 8 ^ ds.length * rest.val = V) :
    emit.put_octal_loop field rest pos ⦃ r => ∃ ds' : List Std.U8, r.1.val = ds' ++ [0#u8] ∧
      (∀ d ∈ ds', 48 ≤ d.val ∧ d.val ≤ 55) ∧ ds'.length = ds.length + pos.val ∧
      octalValue ds' + 8 ^ ds'.length * r.2.val = V ⦄ := by
  unfold emit.put_octal_loop
  apply loop.spec_decr_nat (fun p => p.2.2.val)
    (fun p => ∃ pre ds' : List Std.U8, p.1.val = pre ++ ds' ++ [0#u8] ∧ pre.length = p.2.2.val ∧
      (∀ d ∈ ds', 48 ≤ d.val ∧ d.val ≤ 55) ∧ ds'.length + p.2.2.val = ds.length + pos.val ∧
      octalValue ds' + 8 ^ ds'.length * p.2.1.val = V)
  · rintro ⟨field, rest, pos⟩ ⟨pre, ds, shape, npre, digits, total, value⟩
    simp only at *
    unfold emit.put_octal_loop.body
    split
    · rename_i pos
      step*
      -- the digit goes in front of the digits written, in place of the byte before them
      obtain ⟨pre', x, rfl⟩ : ∃ pre' x, pre = pre' ++ [x] :=
        ⟨pre.dropLast, pre.getLast (by rintro rfl; simp at npre; omega),
          (List.dropLast_append_getLast _).symm⟩
      have low : i.val = rest.val % 8 := by
        rw [i_post, UScalar.val_and, show (7#u64).val = 2 ^ 3 - 1 from rfl,
          Nat.and_two_pow_sub_one_eq_mod]
      have wide : i1.val = i.val := by
        rw [i1_post]; scalar_tac
      have digit : i2.val = 48 + rest.val % 8 := by omega
      have shifted : rest1.val = rest.val / 8 := by rw [rest1_post, Nat.shiftRight_eq_div_pow]
      have where_ : at1.val = pre'.length := by simp at npre; omega
      have placed : s.val = pre' ++ i2 :: ds ++ [0#u8] := by
        rw [s_post, Slice.set_val_eq, shape, where_]
        simp [List.set_append_right]
      refine ⟨⟨pre', i2 :: ds, placed, where_.symm, ?_, ?_, ?_⟩, by omega⟩
      · intro d hd
        rcases List.mem_cons.mp hd with rfl | old
        · omega
        · exact digits d old
      · simp only [List.length_cons]; omega
      · rw [octalValue_cons, List.length_cons, pow_succ, shifted, ← value]
        have : (i2.val - 48) = rest.val % 8 := by omega
        rw [this]
        have e : 8 ^ ds.length * rest.val =
            8 ^ ds.length * (8 * (rest.val / 8) + rest.val % 8) := by
          rw [Nat.div_add_mod]
        rw [e]
        ring
    · rename_i zero
      simp only [Std.WP.spec_ok]
      have : pos.val = 0 := by scalar_tac
      have : pre = [] := List.eq_nil_of_length_eq_zero (by omega)
      subst this
      exact ⟨ds, by simpa using shape, digits, by omega, value⟩
  · exact ⟨pre, ds, shape, npre, digits, rfl, value⟩

/-- What `put_octal` leaves, and when it says it fits: the field is as long as it was; the
number fits when it is below 8 to the number of digits, and then the field is the digits, zeros in
front, and a NUL, and the digits spell the number. -/
theorem put_octal_spec (field : Slice Std.U8) (value : Std.U64) :
    emit.put_octal field value ⦃ r => r.2.length = field.length ∧
      (r.1 = true ↔ 0 < field.length ∧ value.val < 8 ^ (field.length - 1)) ∧
      (r.1 = true → ∃ ds : List Std.U8, r.2.val = ds ++ [0#u8] ∧
        (∀ d ∈ ds, 48 ≤ d.val ∧ d.val ≤ 55) ∧ octalValue ds = value.val) ⦄ := by
  unfold emit.put_octal
  step as ⟨ empty, hempty ⟩
  split
  · rename_i is_empty
    simp only [Std.WP.spec_ok]
    have : field.length = 0 := by simp_all [Slice.length]
    simp [this]
  · rename_i nonempty
    simp only [Slice.len]
    step as ⟨ digits, hdigits ⟩
    step as ⟨ s, hs ⟩
    have hne : field.val ≠ [] := by
      intro h
      apply nonempty
      rw [hempty]
      simp [Slice.length, h]
    have hlen : 0 < field.val.length := List.length_pos_of_ne_nil hne
    have hd : digits.val = field.val.length - 1 := by simp at hdigits; omega
    have shape : s.val = field.val.dropLast ++ [] ++ [0#u8] := by
      have hfv : field.val = field.val.dropLast ++ [field.val.getLast hne] :=
        (List.dropLast_append_getLast hne).symm
      rw [hs, Slice.set_val_eq, hfv]
      simp [List.set_append_right, hd]
    step with put_octal_loop_spec value.val s value digits field.val.dropLast [] shape
      (by simp [hd]) (by simp) (by simp [octalValue]) as ⟨ field1, rest, ds, hfield, hdigs, hlen2, hval ⟩
    have lt := octalValue_lt ds hdigs
    have fl : field.length = field.val.length := rfl
    simp only [List.length_nil, Nat.zero_add] at hlen2
    have l1 : field1.length = field.length := by
      simp only [Slice.length, hfield, List.length_append, List.length_singleton]
      omega
    have gap : ds.length = field.length - 1 := by rw [fl]; omega
    have rest_zero : rest = 0#u64 ↔ rest.val = 0 :=
      ⟨fun h => by simp [h], fun h => UScalar.eq_of_val_eq h⟩
    refine ⟨l1, ?_, ?_⟩
    · -- the digits were enough exactly when nothing is left of the number
      rw [← gap]
      simp only [decide_eq_true_eq, rest_zero]
      constructor
      · intro none_left
        rw [none_left] at hval
        exact ⟨by omega, by omega⟩
      · rintro ⟨_, small⟩
        by_contra nonzero
        have one : 1 ≤ rest.val := by omega
        have : 8 ^ ds.length ≤ 8 ^ ds.length * rest.val := Nat.le_mul_of_pos_right _ one
        linarith
    · intro fits
      simp only [decide_eq_true_eq, rest_zero] at fits
      rw [fits] at hval
      exact ⟨ds, hfield, hdigs, by omega⟩

/-- The loop of `put_decimal` that finds the place of the highest digit: it ends on a power of
ten that is not above the number (or is 1), with the number below ten times it. -/
theorem put_decimal_loop0_spec (value : Std.U64) (scale : Std.U64) (k : Nat)
    (hk : scale.val = 10 ^ k) (below : k = 0 ∨ 10 ^ k ≤ value.val) :
    emit.put_decimal_loop0 value scale ⦃ r => ∃ j, r.val = 10 ^ j ∧
      (j = 0 ∨ 10 ^ j ≤ value.val) ∧ value.val < 10 ^ (j + 1) ⦄ := by
  unfold emit.put_decimal_loop0
  apply loop.spec_decr_nat (fun s => value.val - s.val)
    (fun s => ∃ k, s.val = 10 ^ k ∧ (k = 0 ∨ 10 ^ k ≤ value.val))
  · rintro scale ⟨k, hk, below⟩
    unfold emit.put_decimal_loop0.body
    have pos : 0 < scale.val := by rw [hk]; positivity
    step as ⟨ i, hi ⟩
    split
    · rename_i big
      have ten : 10 ≤ value.val / scale.val := by rw [← hi]; scalar_tac
      have fits : scale.val * 10 ≤ value.val := by have := (Nat.le_div_iff_mul_le pos).mp ten; omega
      step as ⟨ scale1, hscale1 ⟩
      refine ⟨⟨k + 1, by rw [hscale1, hk, pow_succ], Or.inr (by rw [pow_succ, ← hk]; omega)⟩, by omega⟩
    · rename_i small
      have lt : value.val / scale.val < 10 := by rw [← hi]; scalar_tac
      simp only [Std.WP.spec_ok]
      refine ⟨k, hk, below, ?_⟩
      rw [pow_succ, ← hk]
      have := (Nat.div_lt_iff_lt_mul pos).mp lt
      omega
  · exact ⟨k, hk, below⟩

/-- One more digit at the end of the digits read is one more step of the value. -/
theorem decimalValue_snoc (ds : List Std.U8) (d : Std.U8) :
    decimalValue (ds ++ [d]) = 10 * decimalValue ds + (d.val - 48) := by
  simp [decimalValue]

/-- The loop that writes the digits of `V`, the highest first: `scale` is the place of the next
digit, and what is left of the number is below the place after it. -/
theorem put_decimal_loop1_spec (V : Nat) (out : alloc.vec.Vec Std.U8) (scale rest : Std.U64)
    (k : Nat) (hk : scale.val = 10 ^ k) (left : rest.val < 10 ^ (k + 1))
    (first : rest.val = V ∧ (V = 0 ∨ 10 ^ k ≤ V))
    (room : out.val.length + k + 1 ≤ Std.Usize.max) :
    emit.put_decimal_loop1 out scale rest ⦃ r => ∃ ds : List Std.U8, r.val = out.val ++ ds ∧
      (∀ d ∈ ds, 48 ≤ d.val ∧ d.val ≤ 57) ∧ decimalValue ds = V ∧ ds.length = k + 1 ∧
      (V = 0 ∨ ds.head? ≠ some 48#u8) ⦄ := by
  unfold emit.put_decimal_loop1
  -- while a digit is left to write: the digits written so far, the place `10^j` of the next
  -- one, and what is left of the number, below the place before it
  apply loop.spec_decr_nat (fun p => p.2.1.val)
    (fun p => ∃ (ds : List Std.U8), p.1.val = out.val ++ ds ∧
      (∀ d ∈ ds, 48 ≤ d.val ∧ d.val ≤ 57) ∧
      ((∃ j, p.2.1.val = 10 ^ j ∧ p.2.2.val < 10 ^ (j + 1) ∧ ds.length + j + 1 = k + 1 ∧
          decimalValue ds * 10 ^ (j + 1) + p.2.2.val = V) ∨
        (p.2.1.val = 0 ∧ decimalValue ds = V ∧ ds.length = k + 1)) ∧
      (ds = [] → p.2.2.val = V ∧ (V = 0 ∨ 10 ^ k ≤ V)) ∧ (V = 0 ∨ ds.head? ≠ some 48#u8))
  · rintro ⟨cur, scale, rest⟩ ⟨ds, shape, digits, state, start, lead⟩
    dsimp only at shape state start lead ⊢
    unfold emit.put_decimal_loop1.body
    rcases state with ⟨j, hj, hleft, hlen, hval⟩ | ⟨hzero, hv, hlen⟩
    · have pos : 0 < scale.val := by rw [hj]; positivity
      split
      · -- the digit is at most 9: what is left is below ten places
        have ten : rest.val / scale.val < 10 := by
          rw [Nat.div_lt_iff_lt_mul pos, hj, ← pow_succ']; exact hleft
        have cur_room : cur.val.length < Std.Usize.max := by
          have : cur.val.length = out.val.length + ds.length := by simp [shape]
          omega
        step*
        have wide : i1.val = i.val := by rw [i1_post]; scalar_tac
        have digit : i2.val = 48 + rest.val / scale.val := by omega
        have hdiv := Nat.div_add_mod rest.val scale.val
        have hmod : rest.val % scale.val < scale.val := Nat.mod_lt _ pos
        have placed : out1.val = out.val ++ (ds ++ [i2]) := by rw [out1_post, shape]; simp
        have snoc : decimalValue (ds ++ [i2]) = 10 * decimalValue ds + rest.val / scale.val := by
          rw [decimalValue_snoc]; omega
        have lead' : V = 0 ∨ (ds ++ [i2]).head? ≠ some 48#u8 := by
          by_cases none : ds = []
          · subst none
            obtain ⟨hr, hV⟩ := start rfl
            rcases hV with hV | hV
            · exact Or.inl hV
            · right
              have jk : j = k := by simp at hlen; omega
              subst jk
              have : 1 ≤ rest.val / scale.val := by
                rw [Nat.le_div_iff_mul_le pos, hj]; omega
              simp only [List.nil_append, List.head?_cons, ne_eq, Option.some.injEq]
              intro h
              have : i2.val = 48 := by rw [h]; rfl
              omega
          · rcases lead with h | h
            · exact Or.inl h
            · right
              obtain ⟨x, xs, rfl⟩ := List.exists_cons_of_ne_nil none
              simpa using h
        refine ⟨⟨ds ++ [i2], placed, ?_, ?_, fun h => by simp at h, lead'⟩, by omega⟩
        · intro d hd
          rcases List.mem_append.mp hd with old | new
          · exact digits d old
          · simp at new; subst new; omega
        · rcases j with _ | j'
          · -- the last digit: the place was 1
            right
            have one : scale.val = 1 := by simpa using hj
            refine ⟨by omega, ?_, by simp; omega⟩
            rw [snoc, one, Nat.div_one]
            norm_num at hval
            omega
          · left
            refine ⟨j', ?_, ?_, by simp; omega, ?_⟩
            · rw [scale1_post, hj, pow_succ, Nat.mul_div_cancel _ (by norm_num)]
            · rw [rest1_post, ← hj]; exact hmod
            · rw [snoc, rest1_post, ← hj]
              rw [pow_succ, ← hj] at hval
              linarith
      · exfalso; scalar_tac
    · split
      · exfalso; scalar_tac
      · simp only [Std.WP.spec_ok]
        exact ⟨ds, shape, digits, hv, hlen, lead⟩
  · exact ⟨[], by simp, by simp, Or.inl ⟨k, hk, left, by simp, by simp [decimalValue, first.1]⟩,
      fun _ => first, by simp⟩

/-- `put_decimal` appends the digits of the number, the highest first, no zero in front (but for
the number 0, which is one digit), when the vector has room for the 20 digits a 64-bit number has. -/
theorem put_decimal_spec (out : alloc.vec.Vec Std.U8) (value : Std.U64)
    (room : out.val.length + 20 ≤ Std.Usize.max) :
    emit.put_decimal out value ⦃ r => ∃ ds : List Std.U8, r.val = out.val ++ ds ∧
      (∀ d ∈ ds, 48 ≤ d.val ∧ d.val ≤ 57) ∧ decimalValue ds = value.val ∧
      (value.val = 0 → ds = [48#u8]) ∧ (value.val ≠ 0 → ds.head? ≠ some 48#u8) ⦄ := by
  unfold emit.put_decimal
  step with put_decimal_loop0_spec value 1#u64 0 (by simp) (Or.inl rfl) as ⟨ scale, k, hk, below, above ⟩
  have small : k ≤ 19 := by
    by_contra big
    have : 10 ^ 20 ≤ 10 ^ k := Nat.pow_le_pow_right (by norm_num) (by omega)
    have : value.val < 2 ^ 64 := value.hBounds
    rcases below with rfl | below <;> omega
  have first : value.val = value.val ∧ (value.val = 0 ∨ 10 ^ k ≤ value.val) := by
    refine ⟨rfl, ?_⟩
    rcases below with rfl | below
    · by_cases zero : value.val = 0
      · exact Or.inl zero
      · exact Or.inr (by simpa using Nat.one_le_iff_ne_zero.mpr zero)
    · exact Or.inr below
  step with put_decimal_loop1_spec value.val out scale value k hk above first (by omega) as
    ⟨ r, ds, hout, hdigits, hvalue, hlen, hlead ⟩
  refine ⟨ds, hout, hdigits, hvalue, ?_, ?_⟩
  · intro zero
    have k0 : k = 0 := by
      rcases below with h | h
      · exact h
      · have : 0 < 10 ^ k := by positivity
        omega
    subst k0
    rcases ds with _ | ⟨d, _ | ⟨e, t⟩⟩
    · simp at hlen
    · have := hdigits d (by simp)
      simp [decimalValue, zero] at hvalue
      have : d = 48#u8 := UScalar.eq_of_val_eq (by simp; omega)
      simp [this]
    · simp at hlen
  · intro nonzero
    simpa [nonzero] using hlead

/-- The loop of `decimal` on digits only: nothing is invalid, and either no overflow was seen
and the number is the value of the digits, or one was and the digits are above 64 bits. -/
theorem decimal_loop_value (s : Slice Std.U8) :
    decimal_loop ⟨s, 0⟩ 0#u64 false false ⦃ r =>
      (∀ b ∈ s.val, 48 ≤ b.val ∧ b.val ≤ 57) →
        r.2.1 = false ∧ (r.2.2 = false → r.1.val = decimalValue s.val) ∧
        (r.2.2 = true → 2 ^ 64 ≤ decimalValue s.val) ⦄ := by
  unfold decimal_loop
  apply loop.spec_decr_nat (fun p => s.length - p.1.i)
    (fun p => p.1.slice = s ∧ p.1.i ≤ s.length ∧
      ((∀ b ∈ s.val, 48 ≤ b.val ∧ b.val ≤ 57) →
        p.2.2.1 = false ∧ (p.2.2.2 = false → p.2.1.val = decimalValue (s.val.take p.1.i)) ∧
        (p.2.2.2 = true → 2 ^ 64 ≤ decimalValue (s.val.take p.1.i))))
  · rintro ⟨it, value, invalid, overflow⟩ ⟨hs, hi, hall⟩
    simp only at hs hi hall ⊢
    unfold decimal_loop.body
    simp only [core.slice.iter.IteratorSliceIter.next, Slice.len]
    split
    · simp only [Std.bind_ok]
      rename_i inside
      step*
      simp only [lift, Std.bind_ok]
      have wide : (core.convert.num.FromU64U8.from i).val = i.val := by scalar_tac
      have top : core.num.U64.MAX.val = 2 ^ 64 - 1 := by decide
      step*
      all_goals
        subst hs
        have hlt : it.i < it.slice.val.length := by scalar_tac
        have rmax : U64.rMax = 2 ^ 64 - 1 := by decide
      · -- a digit that does not fit: the digits are above 64 bits
        refine ⟨rfl, by scalar_tac, ?_, by scalar_tac⟩
        intro hdigits
        obtain ⟨hvalid, hexact, hover⟩ := hall hdigits
        have hdigit : 48 ≤ it.slice[it.i].val ∧ it.slice[it.i].val ≤ 57 :=
          hdigits _ (List.getElem_mem hlt)
        have hb1 : b1 = true := by rw [b1_post]; exact decide_eq_true hdigit
        have dig : (core.convert.num.FromU64U8.from i).val = it.slice[it.i].val - 48 := by
          rw [wide, i_post, UScalar.val_and, show (15#u8).val = 2 ^ 4 - 1 from rfl,
            Nat.and_two_pow_sub_one_eq_mod]
          omega
        have step_value : decimalValue (List.take (it.i + 1) it.slice.val) =
            10 * decimalValue (List.take it.i it.slice.val) + (it.slice[it.i].val - 48) := by
          rw [List.take_add_one, List.getElem?_eq_getElem hlt]
          exact decimalValue_snoc _ _
        have big : i2.val < value.val := by scalar_tac
        refine ⟨by simp [hvalid, hb1], by simp, fun _ => ?_⟩
        by_cases old : overflow = true
        · have := hover old
          omega
        · have := hexact (by simpa using old)
          omega
      · -- the digit fits: the value takes it in
        refine ⟨rfl, by scalar_tac, ?_, by scalar_tac⟩
        intro hdigits
        obtain ⟨hvalid, hexact, hover⟩ := hall hdigits
        have hdigit : 48 ≤ it.slice[it.i].val ∧ it.slice[it.i].val ≤ 57 :=
          hdigits _ (List.getElem_mem hlt)
        have hb1 : b1 = true := by rw [b1_post]; exact decide_eq_true hdigit
        have dig : (core.convert.num.FromU64U8.from i).val = it.slice[it.i].val - 48 := by
          rw [wide, i_post, UScalar.val_and, show (15#u8).val = 2 ^ 4 - 1 from rfl,
            Nat.and_two_pow_sub_one_eq_mod]
          omega
        have step_value : decimalValue (List.take (it.i + 1) it.slice.val) =
            10 * decimalValue (List.take it.i it.slice.val) + (it.slice[it.i].val - 48) := by
          rw [List.take_add_one, List.getElem?_eq_getElem hlt]
          exact decimalValue_snoc _ _
        refine ⟨by simp [hvalid, hb1], fun none_seen => ?_, fun seen => ?_⟩
        · rw [value1_post, i3_post, dig, step_value, hexact none_seen]
          omega
        · have := hover seen
          omega
    · simp
      subst hs
      have : it.slice.val.length ≤ it.i := by scalar_tac
      intro hdigits
      obtain ⟨hvalid, hexact, hover⟩ := hall hdigits
      rw [List.take_of_length_le this] at hexact hover
      exact ⟨hvalid, hexact, hover⟩
  · simp [decimalValue]

/-- `decimal` of digits (at least one) is their value, or the refusal of a number above 64 bits. -/
theorem decimal_of_digits (s : Slice Std.U8) (digits : ∀ b ∈ s.val, 48 ≤ b.val ∧ b.val ≤ 57)
    (nonempty : s.val ≠ []) :
    decimal s ⦃ r =>
      if decimalValue s.val < 2 ^ 64 then
        ∃ n : Std.U64, r = core.result.Result.Ok n ∧ n.val = decimalValue s.val
      else r = core.result.Result.Err NumError.Overflow ⦄ := by
  unfold decimal
  step as ⟨ empty, hempty ⟩
  step as ⟨ iter, hiter, hfirst ⟩
  obtain rfl : iter = ⟨s, 0⟩ := by cases iter; simp_all
  have not_empty : empty = false := by
    cases empty
    · rfl
    · exfalso; apply nonempty
      have : s.length = 0 := by simpa using hempty.symm
      exact List.eq_nil_of_length_eq_zero this
  subst not_empty
  step with decimal_loop_value s as ⟨ value, invalid, overflow, hall ⟩
  obtain ⟨hvalid, hexact, hover⟩ := hall digits
  simp only [hvalid]
  by_cases seen : overflow = true
  · have := hover seen
    simp [seen]
    omega
  · have fits : decimalValue s.val < 2 ^ 64 := by
      have := hexact (by simpa using seen)
      have : value.val < 2 ^ 64 := value.hBounds
      omega
    simp only [seen, fits, ite_true]
    simp
    exact hexact (by simpa using seen)

/-- The loop of `digits` counts one digit for each division by ten. -/
theorem digits_loop_spec (count rest : Std.Usize) (room : count.val + Nat.log 10 rest.val ≤ Std.Usize.max) :
    emit.digits_loop count rest ⦃ r => r.val = count.val + Nat.log 10 rest.val ⦄ := by
  unfold emit.digits_loop
  apply loop.spec_decr_nat (fun p => p.2.val)
    (fun p => p.1.val + Nat.log 10 p.2.val = count.val + Nat.log 10 rest.val)
  · rintro ⟨count, rest⟩ hsum
    simp only at hsum ⊢
    unfold emit.digits_loop.body
    split
    · rename_i big
      have ten : 10 ≤ rest.val := by scalar_tac
      have logpos : 1 ≤ Nat.log 10 rest.val := Nat.log_pos (by norm_num) ten
      step*
      refine ⟨?_, by omega⟩
      have : Nat.log 10 rest1.val = Nat.log 10 rest.val - 1 := by
        rw [rest1_post, Nat.log_div_base]
      omega
    · rename_i small
      have lt : rest.val < 10 := by scalar_tac
      simp only [Std.WP.spec_ok]
      rw [Nat.log_of_lt lt] at hsum
      omega
  · simp

/-- A length that counts itself is at least `rest` and the digits of `rest`. -/
theorem fixpoint_ge (rest o : Nat) (fix : o = rest + numDigits o) :
    rest + numDigits rest ≤ o := by
  have : numDigits rest ≤ numDigits o := by
    unfold numDigits
    have : rest ≤ o := by omega
    have := Nat.log_mono_right (b := 10) this
    omega
  omega

/-- The digits of `rest + digits(rest)` are those of `rest`, or one more. -/
theorem digits_of_first_try (rest : Nat) :
    numDigits rest ≤ numDigits (rest + numDigits rest) ∧
    numDigits (rest + numDigits rest) ≤ numDigits rest + 1 ∧
    numDigits (rest + numDigits rest + 1) ≤ numDigits rest + 1 := by
  have below : rest < 10 ^ numDigits rest := Nat.lt_pow_succ_log_self (by norm_num) rest
  have room : numDigits rest < 10 ^ numDigits rest := Nat.lt_pow_self (by norm_num)
  have wide : 10 ^ (numDigits rest + 1) = 10 * 10 ^ numDigits rest := by ring
  unfold numDigits at *
  refine ⟨?_, ?_, ?_⟩
  · have := Nat.log_mono_right (b := 10) (show rest ≤ rest + (Nat.log 10 rest + 1) by omega)
    omega
  · have := Nat.log_lt_of_lt_pow (b := 10) (y := rest + (Nat.log 10 rest + 1)) (by omega)
      (show rest + (Nat.log 10 rest + 1) < 10 ^ (Nat.log 10 rest + 1 + 1) by omega)
    omega
  · have := Nat.log_lt_of_lt_pow (b := 10) (y := rest + (Nat.log 10 rest + 1) + 1) (by omega)
      (show rest + (Nat.log 10 rest + 1) + 1 < 10 ^ (Nat.log 10 rest + 1 + 1) by omega)
    omega

/-- `digits` counts the decimal digits of its argument. -/
theorem digits_spec (n : Std.Usize) : emit.digits n ⦃ r => r.val = numDigits n.val ⦄ := by
  unfold emit.digits numDigits
  have small : Nat.log 10 n.val < 20 := by
    have fits := usize_fits_u64 n
    have : n.val < 10 ^ 20 := by
      have : UScalar.max UScalarTy.U64 < 10 ^ 20 := by
        simp
        norm_num [U64.max, U64.numBits]
      omega
    by_cases zero : n.val = 0
    · simp [zero]
    · exact Nat.log_lt_of_lt_pow zero this
  have : 20 ≤ Std.Usize.max := by scalar_tac
  step with digits_loop_spec 1#usize n (by scalar_tac) as ⟨ r, hr ⟩
  omega

/-- `record_len` gives a length that counts itself and is the smallest that does, or `None` when
there is none in a `usize`.  The Rust proves two steps are enough where the first version looped. -/
theorem record_len_spec (rest : Std.Usize) :
    emit.record_len rest ⦃ r => match r with
      | some len => len.val = rest.val + numDigits len.val ∧
          ∀ other, other = rest.val + numDigits other → len.val ≤ other
      | none => ∀ other, other ≤ Std.Usize.max → other ≠ rest.val + numDigits other ⦄ := by
  unfold emit.record_len
  step with digits_spec rest as ⟨ d0, hd0 ⟩
  have hc := Std.Usize.checked_add_bv_spec rest d0
  have ⟨first_ge, first_le, second_le⟩ := digits_of_first_try rest.val
  rcases hadd : Std.Usize.checked_add rest d0 with _ | len0
  · -- the first try does not fit, nor does anything that counts itself
    rw [hadd] at hc
    simp only [lift, Std.bind_ok, core.option.Option.Insts.CoreOpsTry_traitTry.branch,
      core.option.Option.Insts.CoreOpsTry_traitFromResidualOptionNever.from_residual,
      Std.WP.spec_ok]
    intro other fits fix
    have := fixpoint_ge rest.val other fix
    omega
  · rw [hadd] at hc
    obtain ⟨hfit, hlen0, _⟩ := hc
    simp only [lift, Std.bind_ok, core.option.Option.Insts.CoreOpsTry_traitTry.branch]
    step with digits_spec len0 as ⟨ d1, hd1 ⟩
    have same_ge : numDigits len0.val = numDigits (rest.val + numDigits rest.val) := by
      rw [hlen0, hd0]
    split
    · -- the digits of the first try are the ones counted: it counts itself
      rename_i same
      simp only [Std.WP.spec_ok]
      have : numDigits len0.val = numDigits rest.val := by
        have := congrArg Std.UScalar.val same
        omega
      refine ⟨by omega, fun other fix => ?_⟩
      have := fixpoint_ge rest.val other fix
      omega
    · rename_i differs
      have more : numDigits len0.val = numDigits rest.val + 1 := by
        have : d1.val ≠ d0.val := fun h => differs (Std.UScalar.eq_of_val_eq h)
        omega
      have hc1 := Std.Usize.checked_add_bv_spec len0 1#usize
      rcases hadd1 : Std.Usize.checked_add len0 1#usize with _ | len1
      · simp only [Std.WP.spec_ok]
        rw [hadd1] at hc1
        intro other fits fix
        have := fixpoint_ge rest.val other fix
        have : other ≠ len0.val := by
          intro eq
          have : numDigits other = numDigits len0.val := by rw [eq]
          omega
        simp at hc1
        omega
      · simp only [Std.WP.spec_ok]
        rw [hadd1] at hc1
        obtain ⟨_, hlen1, _⟩ := hc1
        have mono : numDigits len0.val ≤ numDigits len1.val := by
          unfold numDigits
          have := Nat.log_mono_right (b := 10) (show len0.val ≤ len1.val by simp at hlen1; omega)
          omega
        have above : numDigits len1.val ≤ numDigits rest.val + 1 := by
          have : len1.val = rest.val + numDigits rest.val + 1 := by simp at hlen1; omega
          rw [this]; exact second_le
        refine ⟨by simp at hlen1; omega, fun other fix => ?_⟩
        have := fixpoint_ge rest.val other fix
        have : other ≠ len0.val := by
          intro eq
          have : numDigits other = numDigits len0.val := by rw [eq]
          omega
        simp at hlen1
        omega


/-- `put_octal` returns, and says it fits exactly when the number is below 8 to the digits of the
field, as Spec.lean says. -/
theorem put_octal_fits_or_is_refused : PutOctalFitsOrIsRefused := by
  intro field value
  have := put_octal_spec field value
  exact Std.WP.spec_mono this (fun r h => ⟨h.1, h.2.1⟩)

/-- `put_octal` writes octal digits and a NUL, as Spec.lean says. -/
theorem put_octal_writes_the_digits : PutOctalWritesTheDigits := by
  intro field value
  refine Std.WP.spec_mono (put_octal_spec field value) (fun r h fits => h.2.2 fits)

/-- What `put_octal` writes is read back by `number`, as Spec.lean says. -/
theorem put_octal_is_read_back : PutOctalIsReadBack := by
  intro field value
  have := put_octal_spec field value
  refine Std.WP.spec_mono this (fun r h fits => ?_)
  obtain ⟨ds, hfield, hdigits, hvalue⟩ := h.2.2 fits
  have read := number_of_octal_digits_is_their_value r.2 ds [] (by simpa using hfield) hdigits
  refine Std.WP.spec_mono read (fun n hn => ?_)
  have small : octalValue ds < 2 ^ 64 := by rw [hvalue]; exact value.hBounds
  simp only [small, ite_true] at hn
  obtain ⟨m, rfl, hm⟩ := hn
  rw [hvalue] at hm
  rw [UScalar.eq_of_val_eq hm]

/-- `put_decimal` writes the digits of the number, as Spec.lean says. -/
theorem put_decimal_writes_the_digits : PutDecimalWritesTheDigits :=
  fun out value room => put_decimal_spec out value room

/-- `decimal` reads digits as their value, as Spec.lean says. -/
theorem decimal_of_digits_is_their_value : DecimalOfDigitsIsTheirValue :=
  fun s digits nonempty => decimal_of_digits s digits nonempty

/-- `record_len` counts itself, as Spec.lean says. -/
theorem record_len_counts_itself : RecordLenCountsItself := record_len_spec

end TarsplitHeader
