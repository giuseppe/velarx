-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: three small facts about lists and numbers that the other files use and
-- that have nothing to do with DNS: changing two bytes next to each other in a list, and what
-- `|||` (or) and `&&&` (and) do to a number and a byte.
--
-- Why it is needed: `put16` writes a number as two bytes, `get16` reads it with a shift and an or,
-- and the proofs need the result as a list and as a sum.
--
-- Read before this file: nothing.
--
-- Notation: `l.set k a` is `l` with its element `k` replaced by `a`; `l.take k` and `l.drop k` are
-- the first `k` elements and the others; `a ||| b` and `a &&& b` are the bitwise or and and of two
-- natural numbers; `a * 256 + b` is the number of the two bytes `a` and `b`.
import Extracted.Funs

namespace DnsCore

/-- Changing two bytes next to each other replaces them in place: the bytes before, the two new
ones, the bytes after. -/
theorem set_two {α : Type} (l : List α) (k : Nat) (a b : α) (inside : k + 2 ≤ l.length) :
    (l.set k a).set (k + 1) b = l.take k ++ [a, b] ++ l.drop (k + 2) := by
  induction k generalizing l with
  | zero =>
    match l, inside with
    | _ :: _ :: rest, _ => simp
  | succ k ih =>
    match l, inside with
    | x :: rest, inside =>
      simp only [List.set_cons_succ, List.take_succ_cons, List.drop_succ_cons, List.cons_append]
      rw [ih rest (by simpa using inside)]

/-- The number `a * 256` or-ed with a byte `b` is their sum (the bits of `b` are free). -/
theorem or_byte (a b : Nat) (byte : b < 256) : a * 256 ||| b = a * 256 + b := by
  have := Nat.shiftLeft_add_eq_or_of_lt (i := 8) (by simpa using byte) a
  simpa [Nat.shiftLeft_eq] using this.symm

/-- Masking with 255 keeps the low byte. -/
theorem and_255 (n : Nat) : n &&& 255 = n % 256 := by
  simpa using Nat.and_two_pow_sub_one_eq_mod n 8

end DnsCore
