-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `alg_len` returns (the table of `AlgorithmLength`: 32 for the
-- algorithm 1, 64 for the algorithm 2, 0 for every other byte, the fs-verity bit being left out),
-- and that no algorithm is longer than 64 bytes, so the digests of `n` algorithm bytes take at
-- most `64 * n`.
-- Why it is needed: `parse` adds the lengths of the algorithms to know how long a head is; the
-- claims about `Done`, `Need` and `most` read those lengths from `AlgorithmLength`.
-- Read before this file: Spec.lean.
-- Notation: `x &&& y` is the bytes `x` and `y` bit by bit; `~~~ x` is the bits of `x` turned over
-- (0x80 is the one bit that says fs-verity, so `~~~ 0x80` is the seven others, 127).
import RequestCore.Spec

open Aeneas Aeneas.Std Result velarx_request_core

namespace RequestCore

/-- The seven low bits of a byte: what is left of it when the fs-verity bit is cleared. -/
theorem clearing_the_fsverity_bit (byte : Std.U8) :
    (byte &&& ~~~ FSVERITY).val = byte.val % 128 := by
  have not_fsverity : (~~~ FSVERITY : Std.U8) = 127#u8 := by
    simp [FSVERITY]; rfl
  rw [not_fsverity, UScalar.val_and]
  have := Nat.and_two_pow_sub_one_eq_mod byte.val 7
  simpa using this

/-- **`alg_len` is the table**: 32 for the algorithm 1, 64 for the algorithm 2, 0 for every other
byte, with or without the fs-verity bit. -/
theorem alg_len_is_the_table : AlgLenIsTheTable := by
  intro byte
  unfold alg_len
  simp only [lift, bind_ok]
  have low_bits := clearing_the_fsverity_bit byte
  by_cases one : byte.val % 128 = 1
  · have : (byte &&& ~~~ FSVERITY) = 1#u8 := by scalar_tac
    simp [this, AlgorithmLength, one]
  · by_cases two : byte.val % 128 = 2
    · have : (byte &&& ~~~ FSVERITY) = 2#u8 := by scalar_tac
      simp [this, AlgorithmLength, two]
    · have not_one : (byte &&& ~~~ FSVERITY) ≠ 1#u8 := by scalar_tac
      have not_two : (byte &&& ~~~ FSVERITY) ≠ 2#u8 := by scalar_tac
      simp [not_one, not_two, AlgorithmLength, one, two]

/-- The same, in the form the proofs of the loops use. -/
theorem alg_len_returns_the_length (byte : Std.U8) :
    alg_len byte ⦃ r => r.val = AlgorithmLength byte ⦄ :=
  alg_len_is_the_table byte

/-- No algorithm is longer than 64 bytes. -/
theorem an_algorithm_is_at_most_64 (byte : Std.U8) : AlgorithmLength byte ≤ 64 := by
  unfold AlgorithmLength
  split_ifs <;> omega

/-- The digests of a list of algorithm bytes take at most 64 bytes each. -/
theorem digests_take_at_most_64_each (algorithms : List Std.U8) :
    (algorithms.map AlgorithmLength).sum ≤ 64 * algorithms.length := by
  induction algorithms with
  | nil => simp
  | cons first rest more =>
    have := an_algorithm_is_at_most_64 first
    simp only [List.map_cons, List.sum_cons, List.length_cons]
    omega

end RequestCore
