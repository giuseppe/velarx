-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proof of `Crc64NeverFails` (Spec.lean):
-- `crc64::update` of crates/tarsplit-header returns for any CRC and any
-- bytes.
--
-- The argument follows the Rust, from the inside:
--   1. the tables are made (`tables`: four loops over 8, 256 and 8 x 256
--      steps, each with a counter that goes up to a bound) without a panic
--      and are 8 arrays of 256 numbers by their type;
--   2. each lookup indexes a table with a byte of the running number (the
--      number masked with 255, or shifted by 56), so below 256
--      (`mask_byte`, `top_byte`, `index_of_byte`);
--   3. `update` cuts the data into words of 8 bytes and the rest
--      (`as_chunks_8`; Models.lean), and two loops go over them.
-- The loops are over a slice (an iterator that goes one byte on), so each
-- ends: what is left of the slice goes down.
--
-- Read before this file: the statement in Spec.lean, and Cstr.lean for the
-- tactics.
--
-- Notation: as in Cstr.lean and Number.lean; `lift e` is a Rust expression
-- that cannot panic (an operation on bits); `^^^` is the bitwise "exclusive
-- or".
import TarsplitHeader.Spec

open Aeneas Aeneas.Std Result velarx_tarsplit_header

namespace TarsplitHeader
/-- A number masked with 255 is below 256 (the default spec of `&&&` does not say it). -/
@[step]
theorem mask_byte (x : Std.U64) : lift (x &&& 255#u64) ⦃ r => r.val < 256 ⦄ := by
  simp only [lift, Std.WP.spec_ok, UScalar.val_and]
  exact lt_of_le_of_lt Nat.and_le_right (by decide)

/-- The top byte of a 64-bit number is below 256. -/
@[step]
theorem top_byte (x : Std.U64) : x >>> 56#i32 ⦃ r => r.val < 256 ⦄ := by
  step*

/-- A number below 256 keeps its value as an index. -/
@[step]
theorem index_of_byte (x : Std.U64) (small : x.val < 256) :
    lift (UScalar.cast .Usize x) ⦃ r => r.val = x.val ⦄ := by
  simp only [lift, Std.WP.spec_ok, UScalar.cast_val_eq]
  exact Nat.mod_eq_of_lt (lt_of_lt_of_le small (by scalar_tac))

/-- The loop that makes an entry of the first table: eight steps, each a shift. -/
@[step]
theorem tables_bits_total (crc : Std.U64) :
    crc64.tables_loop0_loop0 crc 0#i32 ⦃ _ => True ⦄ := by
  unfold crc64.tables_loop0_loop0
  apply loop.spec_decr_nat (fun p => (8 - p.2.val).toNat) (fun p => 0 ≤ p.2.val ∧ p.2.val ≤ 8)
  · rintro ⟨crc, j⟩ ⟨h0, h8⟩
    simp only at h0 h8 ⊢
    unfold crc64.tables_loop0_loop0.body
    split
    · rename_i below
      step as ⟨ bit, hbit ⟩
      by_cases hone : bit = 1#u64
      · simp only [hone, ↓reduceIte]
        step*
        scalar_tac
      · simp only [hone, ↓reduceIte]
        step*
        scalar_tac
    · simp
  · simp

/-- The loop that fills the first table: 256 steps. -/
@[step]
theorem tables_first_total (t : Array (Array Std.U64 256#usize) 8#usize) :
    crc64.tables_loop0 t 0#usize ⦃ _ => True ⦄ := by
  unfold crc64.tables_loop0
  apply loop.spec_decr_nat (fun p => 256 - p.2.val) (fun p => p.2.val ≤ 256)
  · rintro ⟨t, i⟩ hi
    simp only at hi ⊢
    unfold crc64.tables_loop0.body
    split
    · step*
    · simp
  · simp

/-- The loop that fills the entries of table `k` from those of the one before. -/
@[step]
theorem tables_next_total (k : Std.Usize) (one : 1 ≤ k.val) (below : k.val < 8)
    (t : Array (Array Std.U64 256#usize) 8#usize) :
    crc64.tables_loop1_loop0 t k 0#usize ⦃ _ => True ⦄ := by
  unfold crc64.tables_loop1_loop0
  apply loop.spec_decr_nat (fun p => 256 - p.2.val) (fun p => p.2.val ≤ 256)
  · rintro ⟨t, i⟩ hi
    simp only at hi ⊢
    unfold crc64.tables_loop1_loop0.body
    split
    · step*
    · simp
  · simp

/-- The loop over the tables 1 to 7: each is made from the one before. -/
@[step]
theorem tables_rest_total (t : Array (Array Std.U64 256#usize) 8#usize) :
    crc64.tables_loop1 t 1#usize ⦃ _ => True ⦄ := by
  unfold crc64.tables_loop1
  apply loop.spec_decr_nat (fun p => 8 - p.2.val) (fun p => 1 ≤ p.2.val ∧ p.2.val ≤ 8)
  · rintro ⟨t, k⟩ ⟨one, hk⟩
    simp only at one hk ⊢
    unfold crc64.tables_loop1.body
    split
    · step*
      scalar_tac
    · simp
  · simp

/-- Making the tables never panics. -/
@[step]
theorem tables_total : crc64.tables ⦃ _ => True ⦄ := by
  unfold crc64.tables
  step*

/-- The static `TABLES` is the result of `tables`. -/
@[step]
theorem TABLES_total : crc64.TABLES ⦃ _ => True ⦄ := by
  unfold crc64.TABLES
  exact tables_total

/-- The loop over the 8-byte words of the data: a table lookup for each of the
eight bytes of the number, all in the tables made above. -/
@[step]
theorem update_words_total (words : Slice (Array Std.U8 8#usize)) (crc : Std.U64) :
    crc64.update_loop0 ⟨words, 0⟩ crc ⦃ _ => True ⦄ := by
  unfold crc64.update_loop0
  -- the iterator stays on the slice and goes one byte on at each turn
  apply loop.spec_decr_nat (fun p => words.length - p.1.i)
    (fun p => p.1.slice = words ∧ p.1.i ≤ words.length)
  · rintro ⟨it, crc⟩ ⟨hs, hi⟩
    simp only at hs hi ⊢
    unfold crc64.update_loop0.body
    simp only [core.slice.iter.IteratorSliceIter.next, Slice.len]
    split
    · simp only [Std.bind_ok]
      step*
    · simp
  · simp

/-- Widening a byte to 64 bits keeps its value. -/
@[step]
theorem u64_of_byte (b : Std.U8) :
    lift (core.convert.num.FromU64U8.from b) ⦃ r => r.val = b.val ⦄ := by
  simp only [lift, Std.WP.spec_ok]
  scalar_tac

/-- Cutting data into words of 8 bytes returns, for any data. -/
@[step]
theorem as_chunks_8 (data : Slice Std.U8) :
    core.slice.Slice.as_chunks 8#usize data ⦃ _ => True ⦄ := by
  simp [core.slice.Slice.as_chunks]

/-- The loop over the bytes that do not fill a word: one lookup in the first table each. -/
@[step]
theorem update_rest_total (rest : Slice Std.U8) (crc : Std.U64) :
    crc64.update_loop1 ⟨rest, 0⟩ crc ⦃ _ => True ⦄ := by
  unfold crc64.update_loop1
  -- the iterator stays on the slice and goes one byte on at each turn
  apply loop.spec_decr_nat (fun p => rest.length - p.1.i)
    (fun p => p.1.slice = rest ∧ p.1.i ≤ rest.length)
  · rintro ⟨it, crc⟩ ⟨hs, hi⟩
    simp only at hs hi ⊢
    unfold crc64.update_loop1.body
    simp only [core.slice.iter.IteratorSliceIter.next, Slice.len]
    split
    · simp only [Std.bind_ok]
      step*
    · simp
  · simp

/-- `update` returns for any CRC and any data, as Spec.lean says. -/
theorem crc64_never_fails : Crc64NeverFails := by
  intro crc data
  unfold crc64.update
  -- the data is cut into words and a rest, and a loop goes over each
  simp only [lift, Std.bind_ok]
  step as ⟨ words, rest ⟩
  step as ⟨ iter, hiter, hfirst ⟩
  obtain rfl : iter = ⟨words, 0⟩ := by cases iter; simp_all
  step as ⟨ crc2 ⟩
  step as ⟨ iter1, hiter1, hfirst1 ⟩
  obtain rfl : iter1 = ⟨rest, 0⟩ := by cases iter1; simp_all
  step*

end TarsplitHeader
