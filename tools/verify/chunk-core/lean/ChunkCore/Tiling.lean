-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: small facts about `TilesFrom` (Spec.lean), the chunks that tile a part of
-- the file: where they end is decided by where they begin and what they are (`tiles_end_is_unique`);
-- they never end before they begin (`tiles_end_is_not_before_start`); one more chunk that begins
-- where they end makes a longer tiling (`tiles_one_more`); and when the whole list tiles the
-- file, the chunk after the first `k` begins where those `k` end and fits in the rest of the
-- file (`tiles_next_chunk`).
--
-- Why it is needed: the first loop of `check` goes through the chunks one by one, keeping in
-- `tiled` the bytes the chunks so far tile.  These facts are what it takes to say that
-- the loop accepts exactly the lists that tile, and that when it refuses a chunk, the whole list
-- does not tile.
--
-- Read before this file: Spec.lean.
--
-- Notation: `l.take k` is the first `k` elements of the list `l`, `l.drop k` the rest;
-- `l ++ [c]` is the list `l` with `c` at the end; `induction ... with` proves a fact of a list
-- from the fact for the list without its first element.
import ChunkCore.Spec

open Aeneas Aeneas.Std Result velarx_chunk_core

namespace ChunkCore

/-- The chunks that tile from `start` end in one place only. -/
theorem tiles_end_is_unique (chunks : List Chunk) (start stop stop' : Nat)
    (tiles : TilesFrom chunks start stop) (tiles' : TilesFrom chunks start stop') :
    stop = stop' := by
  induction chunks generalizing start with
  | nil => simp only [TilesFrom] at tiles tiles'; omega
  | cons c rest ih => exact ih _ tiles.2.2 tiles'.2.2

/-- The chunks that tile from `start` do not end before it. -/
theorem tiles_end_is_not_before_start (chunks : List Chunk) (start stop : Nat)
    (tiles : TilesFrom chunks start stop) : start ≤ stop := by
  induction chunks generalizing start with
  | nil => simp only [TilesFrom] at tiles; omega
  | cons c rest ih =>
    have := ih _ tiles.2.2
    omega

/-- A chunk of at least a byte that begins where the chunks end makes a tiling that ends where it
does. -/
theorem tiles_one_more (chunks : List Chunk) (start stop : Nat) (c : Chunk)
    (tiles : TilesFrom chunks start stop) (begins_there : c.file_off.val = stop)
    (has_bytes : 0 < c.size.val) :
    TilesFrom (chunks ++ [c]) start (stop + c.size.val) := by
  induction chunks generalizing start with
  | nil =>
    simp only [TilesFrom] at tiles
    simp only [List.nil_append, TilesFrom]
    omega
  | cons d rest ih => exact ⟨tiles.1, tiles.2.1, ih _ tiles.2.2⟩

/-- When the whole list tiles from `start` to `stop`, and its first `k` chunks tile from `start`
to `middle`, then the chunk `k` begins at `middle`, has a byte, and ends no later than `stop`. -/
theorem tiles_next_chunk (chunks : List Chunk) (start middle stop k : Nat)
    (whole : TilesFrom chunks start stop) (first : TilesFrom (chunks.take k) start middle)
    (inside : k < chunks.length) :
    chunks[k].file_off.val = middle ∧ 0 < chunks[k].size.val ∧
      middle + chunks[k].size.val ≤ stop := by
  induction chunks generalizing start k with
  | nil => simp at inside
  | cons c rest ih =>
    cases k with
    | zero =>
      simp only [List.take_zero, TilesFrom] at first
      have := tiles_end_is_not_before_start rest _ stop whole.2.2
      have begins := whole.1
      have has_bytes := whole.2.1
      simp only [List.getElem_cons_zero]
      omega
    | succ k =>
      simp only [List.take_succ_cons, TilesFrom] at first
      exact ih _ k whole.2.2 first.2.2 (by simpa using inside)

end ChunkCore
