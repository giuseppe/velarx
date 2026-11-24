-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the compressed range of a chunk, as a fact about natural numbers
-- (`comp_range_val`: it is the offset of the chunk and `CompEnd`), and what follows when each range
-- passes the tests `check` makes of it one by one (`RangeFits`: it begins at or after the start of
-- the file's range, it does not end before it begins, and a chunk of data has a byte and is within
-- the bound): the ranges are all in the range of the file (`ranges_end_in_the_file`), in order and
-- not overlapping (`ranges_do_not_overlap`), together `ranges_are_good`.
--
-- Why it is needed: the second loop of `check` tests the range of each chunk alone.  The claims of
-- Spec.lean are about all of them together; the end of each range is the offset of the next one,
-- so the one-by-one tests add up to that by induction on the chunks.
--
-- Read before this file: Spec.lean, CheckedSums.lean, and `comp_range` of src/lib.rs.
--
-- Notation: `l[j]` is the element `j` of a list, `l[j]?` the element `j` if there is one;
-- `step as ⟨ x, hx ⟩` runs one Rust line and names its result `x` and what is known of it `hx`;
-- `Nat.le_induction` proves a fact for every number from a given one on, from the fact for the
-- number before.
import ChunkCore.CheckedSums

open Aeneas Aeneas.Std Result velarx_chunk_core

namespace ChunkCore

/-- The range of the last chunk ends where the range of the file ends. -/
theorem comp_end_of_the_last (file : File) (chunks : List Chunk) (j : Nat)
    (last : j + 1 = chunks.length) : CompEnd file chunks j = file.comp_end.val := by
  simp [CompEnd, last]

/-- The range of a chunk that has a chunk after it ends where that chunk begins. -/
theorem comp_end_of_one_with_a_next (file : File) (chunks : List Chunk) (j : Nat)
    (has_next : j + 1 < chunks.length) :
    CompEnd file chunks j = chunks[j + 1].comp_off.val := by
  simp [CompEnd, List.getElem?_eq_getElem has_next]

/-- `comp_range` of the chunk `j` is the offset of the chunk and the end of its range, as
`CompEnd` says.  This is the claim `CompRangeIsTheRangeOfTheChunk` of Spec.lean. -/
@[step]
theorem comp_range_val (file : File) (chunks : Slice Chunk) (j : Std.Usize)
    (below : j.val < chunks.val.length) :
    comp_range file chunks j ⦃ range =>
      range.1.val = chunks.val[j.val].comp_off.val ∧
      range.2.val = CompEnd file chunks.val j.val ⦄ := by
  unfold comp_range
  -- `j + 1` cannot overflow: `j` is the index of a chunk
  step as ⟨ next, hnext ⟩
  dsimp only [Slice.len]
  split
  · -- there is a chunk after it: the range ends at its offset
    rename_i has_next
    have has_next : j.val + 1 < chunks.val.length := by scalar_tac
    step as ⟨ c, hc ⟩
    step as ⟨ c', hc' ⟩
    refine ⟨by rw [hc'], ?_⟩
    rw [comp_end_of_one_with_a_next file chunks.val j.val has_next, hc]
    simp only [hnext]
  · -- it is the last chunk: the range ends where the range of the file does
    rename_i no_next
    have last : j.val + 1 = chunks.val.length := by scalar_tac
    step as ⟨ c, hc ⟩
    refine ⟨by rw [hc], ?_⟩
    rw [comp_end_of_the_last file chunks.val j.val last]

/-- What `check` tests of the compressed range of the chunk `j`, one by one: it begins at or
after the start of the range of the file, it does not end before it begins, and, for a chunk
of data, it has a byte and is within the bound. -/
def RangeFits (file : File) (chunks : List Chunk) (j : Nat) (inside : j < chunks.length) : Prop :=
  file.comp_start.val ≤ chunks[j].comp_off.val ∧
  chunks[j].comp_off.val ≤ CompEnd file chunks j ∧
  (chunks[j].zeros = false → chunks[j].comp_off.val < CompEnd file chunks j ∧
    CompEnd file chunks j ≤ chunks[j].comp_off.val + CompressedBoundOf chunks[j].size.val)

/-- If no range ends before it begins, no range ends after the end of the range of the file:
each ends where the next begins, and the last ends there. -/
theorem ranges_end_in_the_file (file : File) (chunks : List Chunk)
    (each : ∀ (j : Nat) (inside : j < chunks.length), RangeFits file chunks j inside) :
    ∀ j : Nat, j < chunks.length → CompEnd file chunks j ≤ file.comp_end.val := by
  have from_count : ∀ (n j : Nat), j < chunks.length → chunks.length - (j + 1) = n →
      CompEnd file chunks j ≤ file.comp_end.val := by
    intro n
    induction n with
    | zero =>
      -- no chunk after it: it is the last, and ends where the file's range does
      intro j _ count
      rw [comp_end_of_the_last file chunks j (by omega)]
    | succ n ih =>
      -- a chunk after it: its range ends where that begins, which is no later than where the
      -- range of that chunk ends, and by the case of the later chunks that is in the file
      intro j inside count
      have has_next : j + 1 < chunks.length := by omega
      rw [comp_end_of_one_with_a_next file chunks j has_next]
      have this_one := (each (j + 1) has_next).2.1
      have later := ih (j + 1) has_next (by omega)
      omega
  exact fun j inside => from_count _ j inside rfl

/-- If no range ends before it begins, each range ends at or before the place where any chunk
after it begins: each ends where the next begins, and a range does not end before it begins. -/
theorem ranges_do_not_overlap (file : File) (chunks : List Chunk)
    (each : ∀ (j : Nat) (inside : j < chunks.length), RangeFits file chunks j inside) :
    ∀ (j k : Nat) (inside : k < chunks.length), j < k →
      CompEnd file chunks j ≤ chunks[k].comp_off.val := by
  intro j k inside after
  induction k, after using Nat.le_induction with
  | base =>
    rw [comp_end_of_one_with_a_next file chunks j inside]
  | succ k after ih =>
    have before_k : k < chunks.length := by omega
    have this_one := (each k before_k).2.1
    have next_one := comp_end_of_one_with_a_next file chunks k inside
    have earlier := ih before_k
    omega

/-- The ranges that fit one by one are good all together. -/
theorem ranges_are_good (file : File) (chunks : List Chunk)
    (each : ∀ (j : Nat) (inside : j < chunks.length), RangeFits file chunks j inside) :
    RangesAreGood file chunks := by
  refine ⟨fun j inside => ⟨(each j inside).1, (each j inside).2.1,
      ranges_end_in_the_file file chunks each j inside⟩,
    fun j k inside after => ranges_do_not_overlap file chunks each j k inside after,
    fun j inside data => ((each j inside).2.2 data).1,
    fun j inside data => ((each j inside).2.2 data).2⟩

end ChunkCore
