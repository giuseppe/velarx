-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: how the bytes of holes (`HoleBytes`), the bytes of data (`DataBytes`) and
-- the cap of a chunk of data (`DataChunksFitTheCap`) of the first chunks of a list grow when one
-- more chunk is added, and that the first chunks never have more bytes than the whole list.
--
-- Why it is needed: the first loop of `check` keeps the running totals of the chunks it went
-- through.  These are the facts that connect "the total after chunk `k`" to the sums of
-- Spec.lean, for the first `k + 1` chunks and then for all of them.
--
-- Read before this file: Spec.lean.
--
-- Notation: `l.take k` is the first `k` elements of the list `l`; `l.drop k` the others;
-- `l ++ m` the list `l` followed by `m`; `simp [...]` rewrites with the facts in the brackets.
import ChunkCore.Spec

open Aeneas Aeneas.Std Result velarx_chunk_core

namespace ChunkCore

/-- The holes of two lists, one after the other, are the holes of each added. -/
theorem hole_bytes_append (first rest : List Chunk) :
    HoleBytes (first ++ rest) = HoleBytes first + HoleBytes rest := by
  simp [HoleBytes, List.filter_append, List.sum_append]

/-- The data of two lists, one after the other, is the data of each added. -/
theorem data_bytes_append (first rest : List Chunk) :
    DataBytes (first ++ rest) = DataBytes first + DataBytes rest := by
  simp [DataBytes, List.filter_append, List.sum_append]

/-- Adding a hole to the chunks adds its size to the holes and nothing to the data. -/
theorem bytes_after_a_hole (first : List Chunk) (c : Chunk) (hole : c.zeros = true) :
    HoleBytes (first ++ [c]) = HoleBytes first + c.size.val ∧
    DataBytes (first ++ [c]) = DataBytes first := by
  simp [HoleBytes, DataBytes, List.filter_append, List.sum_append, hole]

/-- Adding a chunk of data to the chunks adds its size to the data and nothing to the holes. -/
theorem bytes_after_data (first : List Chunk) (c : Chunk) (data : c.zeros = false) :
    HoleBytes (first ++ [c]) = HoleBytes first ∧
    DataBytes (first ++ [c]) = DataBytes first + c.size.val := by
  simp [HoleBytes, DataBytes, List.filter_append, List.sum_append, data]

/-- The first `k + 1` chunks of a list are its first `k` and the chunk `k`. -/
theorem take_one_more (chunks : List Chunk) (k : Nat) (inside : k < chunks.length) :
    chunks.take (k + 1) = chunks.take k ++ [chunks[k]] := by
  rw [List.take_add_one, List.getElem?_eq_getElem inside]
  rfl

/-- The first chunks of a list have no more holes than the whole list. -/
theorem hole_bytes_of_the_first_are_at_most (chunks : List Chunk) (k : Nat) :
    HoleBytes (chunks.take k) ≤ HoleBytes chunks := by
  have := hole_bytes_append (chunks.take k) (chunks.drop k)
  rw [List.take_append_drop] at this
  omega

/-- The first chunks of a list have no more data than the whole list. -/
theorem data_bytes_of_the_first_are_at_most (chunks : List Chunk) (k : Nat) :
    DataBytes (chunks.take k) ≤ DataBytes chunks := by
  have := data_bytes_append (chunks.take k) (chunks.drop k)
  rw [List.take_append_drop] at this
  omega

/-- A chunk of data that is over the cap is a chunk of the list that makes the cap false. -/
theorem a_chunk_over_the_cap (caps : Caps) (chunks : List Chunk) (k : Nat)
    (inside : k < chunks.length) (data : chunks[k].zeros = false)
    (over : caps.chunk.val < chunks[k].size.val) : ¬ DataChunksFitTheCap caps chunks :=
  fun fits => absurd (fits chunks[k] (List.getElem_mem inside) data) (by omega)

/-- The chunks of the first `k` that fit the cap, and one more chunk that is a hole or fits, fit. -/
theorem fit_the_cap_one_more (caps : Caps) (first : List Chunk) (c : Chunk)
    (fit : DataChunksFitTheCap caps first)
    (this_one : c.zeros = false → c.size.val ≤ caps.chunk.val) :
    DataChunksFitTheCap caps (first ++ [c]) := by
  intro d member data
  rcases List.mem_append.mp member with before | here
  · exact fit d before data
  · rw [List.mem_singleton.mp here]
    exact this_one (List.mem_singleton.mp here ▸ data)

end ChunkCore
