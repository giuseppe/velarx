-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what the loop of `values`, `values` and `integers` answer: the values of
-- the signature follow each other after the 16 bits of the hash, and there are as many as the
-- algorithm has.
-- Why it is needed: it is rule 10 of the header of src/lib.rs: the values lie inside the data, in
-- order, and what follows them is not looked at.
-- Read before this file: BigEndian.lean and Spans.lean.
-- Notation: `Follow start spans finish` is "the spans follow each other from `start` to `finish`".
import SigparseCore.BigEndian
import SigparseCore.Spans
open Aeneas Aeneas.Std Result velarx_sigparse_core
namespace SigparseCore

/-- One more span at the end of spans that follow each other. -/
theorem follow_one_more (start at_ : Nat) (spans : List Span) (span : Span)
    (laid : Follow start spans at_) (after : at_ ≤ span.off.val) :
    Follow start (spans ++ [span]) (span.off.val + span.len.val) := by
  induction spans generalizing start with
  | nil =>
    simp only [Follow] at laid
    subst laid
    exact ⟨after, rfl⟩
  | cons first rest ih =>
    exact ⟨laid.1, ih _ laid.2⟩

/-- The integer a bit count is the number of bytes of (rounded up) is the count of the bits, as
`values` computes it. -/
theorem from_bool_is_small (b : Bool) : (core.convert.num.FromUsizeBool.from b).val ≤ 1 := by
  cases b <;> simp [core.convert.num.FromUsizeBool.from]

/-- The integer a bool is: 1 for true, 0 for false. -/
theorem from_bool_value (b : Bool) :
    (core.convert.num.FromUsizeBool.from b).val = if b = true then 1 else 0 := by
  cases b <;> simp [core.convert.num.FromUsizeBool.from]

/-- The bytes of an integer, as `values` computes them from its bit count (`bits >> 3`, plus one
when `bits & 7` is not 0), are the bit count rounded up to whole bytes. -/
theorem bytes_of_a_bit_count (bits whole rest flag needed : Std.Usize)
    (whole_is : whole.val = bits.val / 8) (rest_is : rest.val = bits.val &&& 7)
    (flag_is : flag.val = (if (rest != 0#usize) = true then 1 else 0))
    (needed_is : needed.val = whole.val + flag.val) : needed.val = (bits.val + 7) / 8 := by
  have rest_mod : rest.val = bits.val % 8 := by
    rw [rest_is]
    have := Nat.and_two_pow_sub_one_eq_mod bits.val 3
    simpa using this
  have rest_ne : (rest != 0#usize) = true ↔ rest.val ≠ 0 := by
    simp [UScalar.eq_equiv]
  by_cases zero : rest.val = 0
  · have : (rest != 0#usize) = false := by simpa [UScalar.eq_equiv] using zero
    simp [this] at flag_is
    omega
  · have : (rest != 0#usize) = true := rest_ne.mpr zero
    simp [this] at flag_is
    omega

/-- Integers end after they begin. -/
theorem integers_end_after (bytes : List Std.U8) (count start finish : Nat)
    (ends : IntegersEnd bytes count start finish) : start ≤ finish := by
  induction count generalizing start with
  | zero => simp only [IntegersEnd] at ends; omega
  | succ count ih =>
    have := ih _ ends
    omega

/-- `count` integers take at least two bytes each. -/
theorem integers_end_room (bytes : List Std.U8) (count start finish : Nat)
    (ends : IntegersEnd bytes count start finish) : start + 2 * count ≤ finish := by
  induction count generalizing start with
  | zero => simp only [IntegersEnd] at ends; omega
  | succ count ih =>
    have := ih _ ends
    omega

/-- One more integer after integers that end where it begins. -/
theorem integers_end_one_more (bytes : List Std.U8) (count start middle : Nat)
    (ends : IntegersEnd bytes count start middle) :
    IntegersEnd bytes (count + 1) start (middle + 2 + (BigEndian bytes middle 2 + 7) / 8) := by
  induction count generalizing start with
  | zero =>
    simp only [IntegersEnd] at ends
    subst ends
    simp [IntegersEnd]
  | succ count ih =>
    exact ih _ ends

/-- `count` integers that are all there, from `position`, take at least two bytes each: they fit
in the data after `position`. -/
theorem integers_room (bytes : List Std.U8) (count position : Nat)
    (integers : IntegersFrom bytes count position) : 2 * count ≤ bytes.length - position := by
  obtain ⟨finish, ends, inside⟩ := integers
  have := integers_end_room _ _ _ _ ends
  omega

/-- The loop of `values` returns, and when it ends with no refusal, the values it holds follow each
other from `start` (where the first of its integers begins) to a position within the data, and there
are as many as there were and `n` more.  One turn reads a bit count of two bytes and the bytes it
needs, or holds a refusal and the next turn ends the loop. -/
theorem values_loop_reads (body : Slice Std.U8) (n : Std.Usize) (values : alloc.vec.Vec Span)
    (at_ : Std.Usize) (fail1 : Option velarx_sigparse_core.Error) (i : Std.Usize)
    (start : Nat) (before : Nat) (turn : i.val ≤ n.val) (inside : at_.val ≤ body.val.length)
    (laid : Follow start values.val at_.val) (from_start : start ≤ at_.val)
    (few : values.val.length ≤ at_.val - start) (counted : values.val.length = before + i.val)
    (ends : IntegersEnd body.val i.val start at_.val) :
    sig.values_loop0 body n values at_ fail1 i ⦃ r =>
      r.2 = none → ∃ finish, Follow start r.1.val finish ∧ finish ≤ body.val.length ∧
        r.1.val.length = before + n.val ∧ IntegersEnd body.val n.val start finish ⦄ := by
  unfold sig.values_loop0
  apply loop.spec_decr_nat
    (fun q => 2 * (n.val - q.2.2.2.val) + (if q.2.2.1.isNone then 1 else 0))
    (fun q => q.2.2.2.val ≤ n.val ∧ q.2.1.val ≤ body.val.length ∧ start ≤ q.2.1.val ∧
      (q.2.2.1 = none → Follow start q.1.val q.2.1.val ∧
        q.1.val.length ≤ q.2.1.val - start ∧ q.1.val.length = before + q.2.2.2.val ∧
        IntegersEnd body.val q.2.2.2.val start q.2.1.val))
  · rintro ⟨values, at_, fail1, i⟩ ⟨turn, inside, from_start, laid⟩
    simp only at turn inside from_start laid ⊢
    unfold sig.values_loop0.body
    dsimp only
    have := body.property
    split
    · rename_i unrefused
      have unrefused : fail1 = none := by cases fail1 <;> simp_all [core.option.Option.is_none]
      subst unrefused
      obtain ⟨laid, few, counted, ends⟩ := laid rfl
      split
      · rename_i more
        have more : i.val < n.val := by scalar_tac
        step with be_reads as ⟨ r, ok_case, err_case ⟩
        cases r with
        | Ok bits =>
          obtain ⟨fits, value⟩ := ok_case bits rfl
          have small : bits.val < 65536 := by
            rw [value]
            simpa using big_endian_below body.val at_.val 2 fits
          step as ⟨ after_bits, hafter_bits ⟩
          step with shift_right_three as ⟨ whole, hwhole ⟩
          step as ⟨ rest, hrest ⟩
          have flag_value := from_bool_value (rest != 0#usize)
          have flag_small := from_bool_is_small (rest != 0#usize)
          generalize core.convert.num.FromUsizeBool.from (rest != 0#usize) = flag at *
          have whole_small : whole.val ≤ 8191 := by omega
          simp only [lift, Std.bind_ok]
          step as ⟨ needed, hneeded ⟩
          have needed_is := bytes_of_a_bit_count bits whole rest flag needed hwhole hrest
            flag_value hneeded
          step with take_gives_the_span as ⟨ r, taken, refused ⟩
          cases r with
          | Ok v =>
            obtain ⟨off_is, len_is, fits_v⟩ := taken v rfl
            have off_val := congrArg UScalar.val off_is
            have len_val := congrArg UScalar.val len_is
            simp only
            step as ⟨ values2, hvalues2 ⟩
            step with span_end_is_the_sum as ⟨ at2, hat2 ⟩
            step as ⟨ next, hnext ⟩
            refine ⟨by omega, by omega, by omega, fun _ => ⟨?_, ?_, ?_, ?_⟩, by omega⟩
            · rw [hvalues2, hat2]
              exact follow_one_more _ _ _ v laid (by omega)
            · rw [hvalues2]
              simp only [List.length_append, List.length_singleton]
              omega
            · rw [hvalues2]
              simp only [List.length_append, List.length_singleton]
              omega
            · have at2_is : at2.val = at_.val + 2 + (BigEndian body.val at_.val 2 + 7) / 8 := by
                rw [hat2]
                omega
              rw [hnext, at2_is]
              exact integers_end_one_more _ _ _ _ ends
          | Err e =>
            step as ⟨ next, hnext ⟩
            exact ⟨by omega, by omega, by omega, fun same => by simp at same, by simp; omega⟩
        | Err e =>
          step as ⟨ next, hnext ⟩
          exact ⟨by omega, by omega, by omega, fun same => by simp at same, by simp; omega⟩
      · rename_i not_more
        have at_end : i.val = n.val := by scalar_tac
        simp only [WP.spec_ok]
        intro _
        rw [at_end] at ends
        exact ⟨at_.val, laid, inside, by omega, ends⟩
    · rename_i refused
      simp only [WP.spec_ok]
      intro none_refused
      simp_all [core.option.Option.is_none]
  · exact ⟨turn, inside, from_start, fun _ => ⟨laid, few, counted, ends⟩⟩

/-- The loop of `values` does not refuse integers that are all there: given `n - i` integers from
`at_` inside the data (`IntegersFrom`), and room in the vector for them, it ends with no
refusal. -/
theorem values_loop_accepts (body : Slice Std.U8) (n : Std.Usize)
    (start_values : alloc.vec.Vec Span) (start_at : Std.Usize) (start_i : Std.Usize)
    (turn : start_i.val ≤ n.val)
    (integers : IntegersFrom body.val (n.val - start_i.val) start_at.val)
    (room : start_values.val.length + (n.val - start_i.val) < Usize.max) :
    sig.values_loop0 body n start_values start_at none start_i ⦃ r => r.2 = none ⦄ := by
  unfold sig.values_loop0
  apply loop.spec_decr_nat
    (fun q => 2 * (n.val - q.2.2.2.val) + (if q.2.2.1.isNone then 1 else 0))
    (fun q => q.2.2.1 = none ∧ q.2.2.2.val ≤ n.val ∧
      IntegersFrom body.val (n.val - q.2.2.2.val) q.2.1.val ∧
      q.1.val.length + (n.val - q.2.2.2.val) < Usize.max)
  · rintro ⟨values, at_, fail1, i⟩ ⟨unrefused, turn, integers, room⟩
    simp only at unrefused turn integers room ⊢
    subst unrefused
    unfold sig.values_loop0.body
    dsimp only
    have := body.property
    split
    · split
      · rename_i more
        have more : i.val < n.val := by scalar_tac
        obtain ⟨c, count⟩ : ∃ c, n.val - i.val = c + 1 := ⟨n.val - i.val - 1, by omega⟩
        rw [count] at integers
        obtain ⟨finish, ends, finish_fits⟩ := integers
        have rest_ends : IntegersEnd body.val c
            (at_.val + 2 + (BigEndian body.val at_.val 2 + 7) / 8) finish := ends
        have fits := le_trans (integers_end_after _ _ _ _ rest_ends) finish_fits
        have rest_integers : IntegersFrom body.val c
            (at_.val + 2 + (BigEndian body.val at_.val 2 + 7) / 8) :=
          ⟨finish, rest_ends, finish_fits⟩
        step with be_reads as ⟨ r, ok_case, err_case ⟩
        cases r with
        | Ok bits =>
          obtain ⟨_, value⟩ := ok_case bits rfl
          have small : bits.val < 65536 := by
            rw [value]
            simpa using big_endian_below body.val at_.val 2 (by omega)
          step as ⟨ after_bits, hafter_bits ⟩
          step with shift_right_three as ⟨ whole, hwhole ⟩
          step as ⟨ rest, hrest ⟩
          have flag_value := from_bool_value (rest != 0#usize)
          have flag_small : (core.convert.num.FromUsizeBool.from (rest != 0#usize)).val ≤ 1 :=
            from_bool_is_small _
          generalize core.convert.num.FromUsizeBool.from (rest != 0#usize) = flag at *
          have whole_small : whole.val ≤ 8191 := by omega
          simp only [lift, Std.bind_ok]
          step as ⟨ needed, hneeded ⟩
          have needed_is := bytes_of_a_bit_count bits whole rest flag needed hwhole hrest
            flag_value hneeded
          step with take_gives_the_span as ⟨ r, taken, refused ⟩
          cases r with
          | Ok v =>
            obtain ⟨off_is, len_is, fits_v⟩ := taken v rfl
            have off_val := congrArg UScalar.val off_is
            have len_val := congrArg UScalar.val len_is
            simp only
            step as ⟨ values2, hvalues2 ⟩
            step with span_end_is_the_sum as ⟨ at2, hat2 ⟩
            step as ⟨ next, hnext ⟩
            have at2_is : at2.val = at_.val + 2 + (BigEndian body.val at_.val 2 + 7) / 8 := by
              rw [hat2]
              omega
            have values_length : values2.val.length = values.val.length + 1 := by
              rw [hvalues2]
              simp
            refine ⟨by omega, ?_, by omega, by simp; omega⟩
            rw [show n.val - next.val = c by omega, at2_is]
            exact rest_integers
          | Err e =>
            have := refused e rfl
            omega
        | Err e =>
          have := err_case e rfl
          omega
      · rename_i not_more
        simp only [WP.spec_ok]
    · simp only [WP.spec_ok]
  · exact ⟨rfl, turn, integers, room⟩

/-- The loop of `values` reads nothing when there is no integer to read: it gives back what it was
given. -/
theorem values_loop_with_nothing_to_read (body : Slice Std.U8) (values : alloc.vec.Vec Span)
    (at_ : Std.Usize) :
    sig.values_loop0 body 0#usize values at_ none 0#usize = ok (values, none) := by
  unfold sig.values_loop0 loop sig.values_loop0.body
  simp [core.option.Option.is_none]

/-- `integers` says how many integers the signature has after the first piece: the number of values
of the algorithm, less the 64 bytes of Ed25519 that are read as they are.  It refuses the other
algorithms, those that have no number of values. -/
theorem integers_count (algo : Std.U8) :
    sig.integers algo ⦃ r =>
      (∀ n, r = core.result.Result.Ok n →
        ValueCount algo.val = some (n.val + (if algo.val = 27 then 1 else 0)) ∧
        (algo.val = 27 → n.val = 0)) ∧
      (∀ e, r = core.result.Result.Err e → ValueCount algo.val = none) ⦄ := by
  unfold sig.integers
  split
  all_goals first
    | (simp only [WP.spec_ok, core.result.Result.Ok.injEq, reduceCtorEq, false_implies,
        implies_true, and_true]
       rintro n rfl
       simp only [ValueCount, UScalar.val, BitVec.reduceToNat]
       decide)
    | (simp only [WP.spec_ok, reduceCtorEq, false_implies, implies_true, true_and]
       intro e _
       rename_i _ not_1 not_3 not_17 not_19 not_22 not_27 _
       have n1 : algo.val ≠ 1 := fun same => not_1 (UScalar.eq_of_val_eq (same.trans rfl))
       have n3 : algo.val ≠ 3 := fun same => not_3 (UScalar.eq_of_val_eq (same.trans rfl))
       have n17 : algo.val ≠ 17 := fun same => not_17 (UScalar.eq_of_val_eq (same.trans rfl))
       have n19 : algo.val ≠ 19 := fun same => not_19 (UScalar.eq_of_val_eq (same.trans rfl))
       have n22 : algo.val ≠ 22 := fun same => not_22 (UScalar.eq_of_val_eq (same.trans rfl))
       have n27 : algo.val ≠ 27 := fun same => not_27 (UScalar.eq_of_val_eq (same.trans rfl))
       simp [ValueCount, n1, n3, n17, n19, n22, n27])

/-- The second loop of `values` is the first: the same code. -/
theorem second_values_loop_is_the_first (body : Slice Std.U8) (n : Std.Usize)
    (values : alloc.vec.Vec Span) (at_ : Std.Usize) (fail1 : Option velarx_sigparse_core.Error)
    (i : Std.Usize) :
    sig.values_loop1 body n values at_ fail1 i = sig.values_loop0 body n values at_ fail1 i := rfl

/-- `values` reads the values of a signature (the 64 bytes of Ed25519, or integers): it returns, and
when it accepts, they follow each other from `at_` to a position within the data, and there are `n`
(and one more for Ed25519). -/
theorem values_reads (body : Slice Std.U8) (at_ : Std.Usize) (algo : Std.U8) (n : Std.Usize)
    (inside : at_.val ≤ body.val.length) (nothing_more : algo.val = 27 → n.val = 0) :
    sig.values body at_ algo n ⦃ r =>
      ∀ values, r = core.result.Result.Ok values →
        ∃ finish, Follow at_.val values.val finish ∧ finish ≤ body.val.length ∧
          values.val.length = n.val + (if algo.val = 27 then 1 else 0) ∧
          (algo.val = 27 → at_.val + 64 ≤ body.val.length) ∧
          (algo.val ≠ 27 → IntegersFrom body.val n.val at_.val) ⦄ := by
  unfold sig.values
  have := body.property
  split
  · rename_i is_ed25519
    have ed : algo.val = 27 := by
      have := congrArg UScalar.val is_ed25519
      simpa [sig.ALGO_ED25519] using this
    step with take_gives_the_span as ⟨ r, taken, refused ⟩
    cases r with
    | Ok piece =>
      obtain ⟨off_is, len_is, fits⟩ := taken piece rfl
      have off_val := congrArg UScalar.val off_is
      have len_val := congrArg UScalar.val len_is
      simp only [core.result.Result.Insts.CoreOpsTry.branch, Std.bind_ok]
      step as ⟨ values, hvalues ⟩
      have n_zero : n = 0#usize := UScalar.eq_of_val_eq (by simpa using nothing_more ed)
      rw [n_zero, values_loop_with_nothing_to_read]
      refine WP.spec_bind (Pₘ := fun x => x = (values, none)) ((WP.spec_ok _).mpr rfl) ?_
      rintro ⟨values1, fail1⟩ same
      simp only [Prod.mk.injEq] at same
      obtain ⟨rfl, rfl⟩ := same
      change ok (core.result.Result.Ok values1) ⦃ _ ⦄
      simp only [WP.spec_ok, core.result.Result.Ok.injEq]
      rintro vs rfl
      refine ⟨at_.val + 64, ?_, by omega, ?_, fun _ => by omega, fun not_ed => absurd ed not_ed⟩
      · have empty : (alloc.vec.Vec.new Span).val = [] := rfl
        have len_64 : piece.len.val = 64 := by simpa using len_val
        rw [hvalues, empty]
        simp only [List.nil_append, Follow]
        omega
      · simp [hvalues, ed]
    | Err e =>
      simp [core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual]
  · rename_i not_ed25519
    have not_ed : algo.val ≠ 27 := by
      intro same
      exact not_ed25519 (UScalar.eq_of_val_eq (by simpa [sig.ALGO_ED25519] using same))
    have loop_reads := values_loop_reads body n (alloc.vec.Vec.new Span) at_ none 0#usize at_.val 0
      (by simp) inside (by simp [alloc.vec.Vec.new, Follow]) le_rfl (by simp [alloc.vec.Vec.new])
      (by simp [alloc.vec.Vec.new]) (by simp [IntegersEnd])
    rw [second_values_loop_is_the_first]
    step with loop_reads as ⟨ values, fail1, finished ⟩
    cases fail1 with
    | none =>
      simp only [WP.spec_ok, core.result.Result.Ok.injEq]
      rintro vs rfl
      obtain ⟨finish, laid, fits, count, ends⟩ := finished rfl
      exact ⟨finish, laid, fits, by simp [count, not_ed], fun is_ed => absurd is_ed not_ed,
        fun _ => ⟨finish, by simpa using ends, fits⟩⟩
    | some e =>
      simp only [WP.spec_ok, reduceCtorEq, false_implies, implies_true]

/-- `values` does not refuse values that are all there: the 64 bytes of Ed25519 (and no integer
after them), or the `n` integers (`IntegersFrom`), from `at_`, inside the data. -/
theorem values_accepts (body : Slice Std.U8) (at_ : Std.Usize) (algo : Std.U8) (n : Std.Usize)
    (nothing_more : algo.val = 27 → n.val = 0)
    (ed25519 : algo.val = 27 → at_.val + 64 ≤ body.val.length)
    (integers : algo.val ≠ 27 → IntegersFrom body.val n.val at_.val) :
    sig.values body at_ algo n ⦃ r => ∃ values, r = core.result.Result.Ok values ⦄ := by
  unfold sig.values
  have := body.property
  split
  · rename_i is_ed25519
    have ed : algo.val = 27 := by
      have := congrArg UScalar.val is_ed25519
      simpa [sig.ALGO_ED25519] using this
    step with take_gives_the_span as ⟨ r, taken, refused ⟩
    cases r with
    | Ok piece =>
      simp only [core.result.Result.Insts.CoreOpsTry.branch, Std.bind_ok]
      step as ⟨ values, hvalues ⟩
      have n_zero : n = 0#usize := UScalar.eq_of_val_eq (by simpa using nothing_more ed)
      rw [n_zero, values_loop_with_nothing_to_read]
      refine WP.spec_bind (Pₘ := fun x => x = (values, none)) ((WP.spec_ok _).mpr rfl) ?_
      rintro ⟨values1, fail1⟩ same
      simp only [Prod.mk.injEq] at same
      obtain ⟨rfl, rfl⟩ := same
      exact (WP.spec_ok _).mpr ⟨_, rfl⟩
    | Err e =>
      have := refused e rfl
      have := ed25519 ed
      omega
  · rename_i not_ed25519
    have not_ed : algo.val ≠ 27 := by
      intro same
      exact not_ed25519 (UScalar.eq_of_val_eq (by simpa [sig.ALGO_ED25519] using same))
    have room : (alloc.vec.Vec.new Span).val.length + (n.val - 0#usize.val) < Usize.max := by
      have := integers_room body.val n.val at_.val (integers not_ed)
      simp [alloc.vec.Vec.new]
      have : 0 < Usize.max := by scalar_tac
      omega
    have loop_accepts := values_loop_accepts body n (alloc.vec.Vec.new Span) at_ 0#usize (by simp)
      (by simpa using integers not_ed) room
    rw [second_values_loop_is_the_first]
    step with loop_accepts as ⟨ values, fail1, finished ⟩
    subst finished
    exact (WP.spec_ok _).mpr ⟨_, rfl⟩

end SigparseCore
