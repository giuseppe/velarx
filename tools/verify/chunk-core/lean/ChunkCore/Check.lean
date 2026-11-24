-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `check` (crates/chunk-core) returns, as one fact (`check_judges`):
-- its answer is `Judged`, that is, if it accepts, `Accepted` (the chunks tile the file, the caps
-- hold, the totals are the sums, the ranges are good), and if it refuses, the refusal names a
-- false statement (`Named`).  It puts together the two loops (WalkTheChunks.lean,
-- WalkTheRanges.lean) and the last test of `check`, that the chunks reach the end of the file.
--
-- Why it is needed: each claim of Spec.lean is a part of this fact, and the completeness claim
-- (a good list is accepted) follows from it: a refusal names a false statement, and a good list
-- has none.
--
-- Read before this file: Spec.lean, WalkTheChunks.lean, WalkTheRanges.lean, and `check` in
-- src/lib.rs.
--
-- Notation: as in WalkTheChunks.lean; `cases refusal with | none | some why` makes the two cases
-- (nothing refused, or refused for `why`); `Std.uncurry_apply_pair` is the fact that `let (a, b) :=
-- (x, y)` is `x` and `y`.
import ChunkCore.WalkTheRanges

open Aeneas Aeneas.Std Result velarx_chunk_core

namespace ChunkCore

/-- What an accepted answer `t` satisfies: the chunks tile the file; no chunk of data is over the
cap; the totals are `before` plus the holes and the data; each total is within its cap when
`before` was; and, for a file that is placed, the ranges are good.  Each claim of Spec.lean
about an accepted answer is a part of this. -/
structure Accepted (file : File) (chunks : List Chunk) (caps : Caps) (before : Totals)
    (t : Totals) : Prop where
  /-- The chunks tile the file. -/
  tiles : Tiles file chunks
  /-- No chunk of data is over the cap of a chunk. -/
  fits : DataChunksFitTheCap caps chunks
  /-- The total of the holes is `before` plus the holes of the chunks. -/
  zeros_sum : t.zeros.val = before.zeros.val + HoleBytes chunks
  /-- The total of the data is `before` plus the data of the chunks. -/
  planned_sum : t.planned.val = before.planned.val + DataBytes chunks
  /-- The total of the holes is within its cap if `before` was. -/
  zeros_within : before.zeros.val ≤ caps.zeros.val → t.zeros.val ≤ caps.zeros.val
  /-- The total of the data is within its cap if `before` was. -/
  planned_within : before.planned.val ≤ caps.planned.val → t.planned.val ≤ caps.planned.val
  /-- The compressed ranges are good, for a file that is placed. -/
  ranges : file.placed = true → RangesAreGood file chunks

/-- What the answer of `check` satisfies: if it is accepted with totals `t`, then `Accepted`; if
it is refused for `why`, then `Named why` (the statement the refusal says is false of the
input). -/
def Judged (file : File) (chunks : List Chunk) (caps : Caps) (before : Totals)
    (answer : core.result.Result Totals Refusal) : Prop :=
  (∀ t, answer = core.result.Result.Ok t → Accepted file chunks caps before t) ∧
  (∀ why, answer = core.result.Result.Err why → Named why file chunks caps before)

/-- The first loop saw every chunk, they tile the whole file, and the ranges are good when they
are looked at: this is what an accepted answer says. -/
theorem accepted_after_the_walk (file : File) (chunks : List Chunk) (caps : Caps)
    (before totals : Totals) (tiled : Std.U64) (all_tiled : tiled.val = file.size.val)
    (tiled_all : Tiled file chunks chunks.length tiled)
    (counted_all : Counted caps before chunks chunks.length totals)
    (ranges : file.placed = true → RangesAreGood file chunks) :
    Accepted file chunks caps before totals := by
  obtain ⟨zeros, planned, zeros_fit, planned_fit, chunks_fit⟩ := counted_all
  rw [List.take_length] at zeros planned chunks_fit
  refine ⟨?_, chunks_fit, zeros, planned, zeros_fit, planned_fit, ranges⟩
  have tiles : TilesFrom chunks 0 tiled.val := by
    have := tiled_all.1
    rwa [List.take_length] at this
  rw [Tiles, ← all_tiled]
  exact tiles

/-- `check` returns, and its answer is `Judged`.  This is the whole proof of `check`: the first
loop (`walk_the_chunks`) judges the tiling and the caps; if it has not refused and the totals
tile the file, the second loop (`walk_the_ranges`) judges the ranges of a placed file; the
answer is accepted when none refused.  The claims of Spec.lean are read from it in Claims.lean. -/
theorem check_judges (file : File) (chunks : Slice Chunk) (caps : Caps) (before : Totals) :
    check file chunks caps before ⦃ answer => Judged file chunks.val caps before answer ⦄ := by
  unfold check
  -- the first loop
  refine WP.spec_bind (walk_the_chunks file chunks caps before) ?_
  rintro ⟨file1, totals, refusal, tiled⟩ ⟨rfl, outcome⟩
  simp only [Std.uncurry_apply_pair] at outcome ⊢
  cases refusal with
  | some why =>
    -- the first loop refused: nothing else is looked at
    split
    · rename_i refused
      exact absurd refused (by simp)
    · simp only [Std.bind_ok, Std.uncurry_apply_pair]
      split
      · rename_i unrefused
        exact absurd unrefused (by simp)
      · refine (WP.spec_ok _).mpr ?_
        exact ⟨(fun _ h => nomatch h), fun _ h => by cases h; exact outcome⟩
  | none =>
    -- the first loop did not refuse: the last test is that the chunks reach the end of the file
    obtain ⟨tiled_all, counted_all⟩ := outcome
    split
    · rename_i unrefused
      split
      · rename_i short
        simp only [Std.bind_ok, Std.uncurry_apply_pair]
        split
        · rename_i refused
          exact absurd refused (by simp)
        · refine (WP.spec_ok _).mpr ?_
          refine ⟨(fun _ h => nomatch h), fun _ h => ?_⟩
          cases h
          intro tiles
          have same := tiles_end_is_unique chunks.val 0 tiled.val file1.size.val
            (by simpa using tiled_all.1) tiles
          have : tiled.val ≠ file1.size.val := by simpa using short
          exact this same
      · -- they do: the second loop, for a file that is placed
        rename_i all_tiled
        have all_tiled : tiled.val = file1.size.val := by simpa using all_tiled
        simp only [Std.bind_ok, Std.uncurry_apply_pair]
        split
        · rename_i unrefused_still
          split
          · rename_i placed
            refine WP.spec_bind (walk_the_ranges file1 chunks caps before placed) ?_
            intro refusal2 placing
            cases refusal2 with
            | some why =>
              refine (WP.spec_ok _).mpr ⟨(fun _ h => nomatch h), fun _ h => ?_⟩
              cases h
              exact placing
            | none =>
              have ranges := ranges_are_good file1 chunks.val
                (fun j inside => placing j inside inside)
              refine (WP.spec_ok _).mpr ⟨fun _ h => ?_, (fun _ h => nomatch h)⟩
              cases h
              exact accepted_after_the_walk file1 chunks.val caps before totals tiled all_tiled
                tiled_all counted_all (fun _ => ranges)
          · rename_i not_placed
            refine (WP.spec_ok _).mpr ⟨fun _ h => ?_, (fun _ h => nomatch h)⟩
            cases h
            exact accepted_after_the_walk file1 chunks.val caps before totals tiled all_tiled
              tiled_all counted_all (fun placed => absurd placed not_placed)
        · rename_i refused
          exact absurd rfl refused
    · rename_i refused
      exact absurd rfl refused

end ChunkCore
