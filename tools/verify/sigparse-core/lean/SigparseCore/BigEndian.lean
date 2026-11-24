-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the number made of the bytes at a position (`BigEndian`), what the loop of
-- `be` computes, what `be` answers, and three small machine steps the other proofs use (a byte
-- widened to a `usize`, a shift left by a byte, a shift right by three bits).
-- Why it is needed: every length of the formats is read by `be`, a big endian number of at most 4
-- bytes: that it returns, and the number it gives, is what every other proof starts from.  The loop
-- keeps `v` as the number of the first `i` bytes; as at most 4 are read, the shift never loses a
-- bit.
-- Read before this file: Spec.lean (`BigEndian`).
-- Notation: `be data at n ⦃ r => P r ⦄` is "`be` returns, and its answer satisfies `P`"; `step with
-- T as ⟨ x, hx ⟩` runs one line of the Rust function with the theorem `T` and names its result `x`
-- and what is known of it `hx`; `scalar_tac` and `omega` decide facts about numbers.
import SigparseCore.Spec
open Aeneas Aeneas.Std Result velarx_sigparse_core
namespace SigparseCore

/-- One more byte at the end of the bytes read. -/
theorem big_endian_one_more (bytes : List Std.U8) (start i : Nat)
  (inside : start + i < bytes.length) :
    BigEndian bytes start (i + 1) = BigEndian bytes start i * 256 + bytes[start + i].val := by
  unfold BigEndian
  rw [List.take_add_one, List.foldl_append]
  have : (bytes.drop start)[i]? = some bytes[start + i] := by simp [List.getElem?_drop]
  rw [this]
  simp

theorem big_endian_none (bytes : List Std.U8) (start : Nat) : BigEndian bytes start 0 = 0 := by
  simp [BigEndian]

theorem big_endian_below (bytes : List Std.U8) (start n : Nat) (inside : start + n ≤ bytes.length) :
    BigEndian bytes start n < 256 ^ n := by
  induction n with
  | zero => simp [BigEndian]
  | succ i ih =>
    rw [big_endian_one_more bytes start i (by omega), pow_succ]
    have := ih (by omega)
    have : bytes[start + i].val < 256 := by scalar_tac
    omega

/-- A byte widened to a `usize` (`usize::from`) keeps its value. -/
theorem widen_a_byte (byte : Std.U8) :
    lift (core.convert.num.FromUsizeU8.from byte) ⦃ r => r.val = byte.val ⦄ := by
  simp only [lift, WP.spec_ok]
  exact core.convert.num.FromUsizeU8.from_val_eq byte

/-- Shifting a small number left by a byte is the product with 256: nothing is lost. -/
theorem shift_left_a_byte (v : Std.Usize) (small : v.val < 2 ^ 24) :
    v <<< 8#i32 ⦃ r => r.val = v.val * 256 ⦄ := by
  have room : 2 ^ 32 ≤ Usize.size := by scalar_tac
  step as ⟨ shifted, hshifted ⟩
  · cases System.Platform.numBits_eq <;> simp [*]
  rw [hshifted, Nat.shiftLeft_eq, Nat.mod_eq_of_lt (by omega)]

/-- Shifting a number right by three bits divides it by 8. -/
theorem shift_right_three (v : Std.Usize) : v >>> 3#i32 ⦃ r => r.val = v.val / 8 ⦄ := by
  step as ⟨ shifted, hshifted ⟩
  · cases System.Platform.numBits_eq <;> simp [*]
  rw [hshifted, Nat.shiftRight_eq_div_pow]

/-- Or-ing a byte into a number whose last byte is empty adds it. -/
theorem or_in_a_byte (v b : Std.Usize) (empty : v.val % 256 = 0) (byte : b.val < 256) :
    lift (v ||| b) ⦃ r => r.val = v.val + b.val ⦄ := by
  step as ⟨ joined, hjoined, _ ⟩
  rw [hjoined, UScalar.val_or]
  have : v.val = (v.val / 256) <<< 8 := by rw [Nat.shiftLeft_eq]; omega
  rw [this, ← Nat.shiftLeft_add_eq_or_of_lt (by simpa using byte)]

/-- The loop of `be`: after `i` turns, `v` is the number of the first `i` bytes. -/
theorem be_loop_reads (data : Slice Std.U8) (at_ n : Std.Usize) (v i : Std.Usize)
    (few : n.val ≤ 4) (inside : at_.val + n.val ≤ data.val.length) (turn : i.val ≤ n.val)
    (value : v.val = BigEndian data.val at_.val i.val) :
    be_loop data at_ n v i ⦃ r => r.val = BigEndian data.val at_.val n.val ⦄ := by
  unfold be_loop
  apply loop.spec_decr_nat (fun q => n.val - q.2.val)
    (fun q => q.2.val ≤ n.val ∧ q.1.val = BigEndian data.val at_.val q.2.val)
  · rintro ⟨v, i⟩ ⟨turn, value⟩
    simp only at turn value ⊢
    unfold be_loop.body
    split
    · rename_i below
      have below : i.val < n.val := by scalar_tac
      have small : v.val < 2 ^ 24 := by
        have := big_endian_below data.val at_.val i.val (by omega)
        have : 256 ^ i.val ≤ 256 ^ 3 := Nat.pow_le_pow_right (by omega) (by omega)
        omega
      step with shift_left_a_byte as ⟨ shifted, hshifted ⟩
      have in_data : at_.val + i.val < data.val.length := by omega
      have := data.property
      step as ⟨ at_i, hat_i ⟩
      step as ⟨ byte, hbyte ⟩
      step with widen_a_byte as ⟨ widened, hwidened ⟩
      step with or_in_a_byte as ⟨ joined, hjoined ⟩
      step as ⟨ next, hnext ⟩
      have byte_is : data.val[at_.val + i.val] = byte := by simp_all
      refine ⟨by omega, ?_, by omega⟩
      rw [hjoined, hshifted, value, hnext, big_endian_one_more data.val _ _ in_data, byte_is,
        hwidened]
    · rename_i done
      have : i.val = n.val := by scalar_tac
      simp only [WP.spec_ok]
      rw [value, this]
  · exact ⟨turn, value⟩

/-- `be` reads `n` bytes (at most 4) when they are all there, and says so otherwise: it returns, and
its answer is the number of the bytes, or a refusal because the input ends before them. -/
theorem be_reads (data : Slice Std.U8) (at_ n : Std.Usize) (few : n.val ≤ 4) :
    be data at_ n ⦃ r =>
      (∀ v, r = core.result.Result.Ok v →
        at_.val + n.val ≤ data.val.length ∧ v.val = BigEndian data.val at_.val n.val) ∧
      (∀ e, r = core.result.Result.Err e → data.val.length < at_.val + n.val) ⦄ := by
  unfold be
  dsimp only [Slice.len]
  split
  · rename_i past
    simp only [WP.spec_ok, reduceCtorEq, false_implies, implies_true, true_and]
    intro e _
    scalar_tac
  · rename_i inside
    step as ⟨ room, hroom ⟩
    split
    · rename_i short
      simp only [WP.spec_ok, reduceCtorEq, false_implies, implies_true, true_and]
      intro e _
      scalar_tac
    · rename_i fits
      step with be_loop_reads as ⟨ v, hv ⟩
      · simp [big_endian_none]
      simp only [reduceCtorEq, false_implies, implies_true, and_true]
      intro v' same
      cases same
      exact ⟨by scalar_tac, hv⟩

end SigparseCore
