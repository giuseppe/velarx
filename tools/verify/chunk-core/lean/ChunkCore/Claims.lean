-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the claims of Spec.lean, one theorem for each, in the order
-- of Spec.lean.
--
-- Why it is needed: ../Theorems.lean names what is proved; the proofs are here.  They are short
-- because the work is in the files before this one: `check_judges` (Check.lean) says, of the
-- answer of `check`, everything the claims need (`Judged`: what an accepted answer satisfies, and
-- what a refused one names), and each claim below reads its part.
--
-- Read before this file: Spec.lean, then Check.lean.
--
-- Notation: `WP.spec_mono h f` is "use what `h` says of the function, and `f` to show that it is
-- enough"; `judged.1 t accepted` is the first part of `judged` (what an accepted answer satisfies)
-- for the totals `t` of the answer, and `.tiles`, `.fits`, ... are its named parts; `cases answer` is "there are two answers: accepted, or refused".
import ChunkCore.Check

open Aeneas Aeneas.Std Result velarx_chunk_core

namespace ChunkCore

/-- `compressed_bound` returns the formula, cut at the largest `u64`. -/
theorem compressed_bound_is_the_formula : CompressedBoundIsTheFormula :=
  fun size => compressed_bound_val size

/-- `comp_range` returns the offset of the chunk and where its range ends. -/
theorem comp_range_is_the_range_of_the_chunk : CompRangeIsTheRangeOfTheChunk :=
  fun file chunks j below => comp_range_val file chunks j below

/-- `check` returns: `check_judges` says it, and says it of every input. -/
theorem check_always_returns : CheckAlwaysReturns :=
  fun file chunks caps before =>
    WP.spec_mono (check_judges file chunks caps before) (fun _ _ => trivial)

/-- An accepted answer is `Accepted`, which begins with the tiling. -/
theorem accepted_chunks_tile_the_file : AcceptedChunksTileTheFile :=
  fun file chunks caps before =>
    WP.spec_mono (check_judges file chunks caps before)
      (fun _ judged t answered => (judged.1 t answered).tiles)

/-- An accepted answer is `Accepted`, which has the cap of the chunks of data. -/
theorem accepted_data_chunks_fit_the_cap : AcceptedDataChunksFitTheCap :=
  fun file chunks caps before =>
    WP.spec_mono (check_judges file chunks caps before)
      (fun _ judged t answered => (judged.1 t answered).fits)

/-- An accepted answer is `Accepted`, which has the two sums. -/
theorem accepted_totals_are_the_sums : AcceptedTotalsAreTheSums :=
  fun file chunks caps before =>
    WP.spec_mono (check_judges file chunks caps before)
      (fun _ judged t answered =>
        ⟨(judged.1 t answered).zeros_sum, (judged.1 t answered).planned_sum⟩)

/-- An accepted answer is `Accepted`, which keeps each total within its cap when `before` was. -/
theorem accepted_totals_are_within_the_caps : AcceptedTotalsAreWithinTheCaps :=
  fun file chunks caps before zeros_within planned_within =>
    WP.spec_mono (check_judges file chunks caps before)
      (fun _ judged t answered =>
        ⟨(judged.1 t answered).zeros_within zeros_within,
         (judged.1 t answered).planned_within planned_within⟩)

/-- An accepted answer is `Accepted`, which has the good ranges for a placed file; two of the
four are the claim. -/
theorem accepted_ranges_are_in_the_file_in_order : AcceptedRangesAreInTheFileInOrder :=
  fun file chunks caps before =>
    WP.spec_mono (check_judges file chunks caps before)
      (fun _ judged t answered placed =>
        ⟨((judged.1 t answered).ranges placed).1,
         ((judged.1 t answered).ranges placed).2.1⟩)

/-- The other two of the four. -/
theorem accepted_data_ranges_have_bytes_within_the_bound :
    AcceptedDataRangesHaveBytesWithinTheBound :=
  fun file chunks caps before =>
    WP.spec_mono (check_judges file chunks caps before)
      (fun _ judged t answered placed =>
        ⟨((judged.1 t answered).ranges placed).2.2.1,
         ((judged.1 t answered).ranges placed).2.2.2⟩)

/-- What a refusal names is false when the chunks are good: each of the six statements is one
of the parts of `Good`, negated. -/
theorem nothing_good_is_named (file : File) (chunks : List Chunk) (caps : Caps)
    (before : Totals) (good : Good file chunks caps before) (why : Refusal) :
    ¬ Named why file chunks caps before := by
  obtain ⟨tiles, chunks_fit, holes_fit, data_fits, ranges⟩ := good
  cases why with
  | NotTiled => exact fun not_tiled => not_tiled tiles
  | ChunkTooBig => exact fun too_big => too_big chunks_fit
  | TooManyZeros => exact fun too_many => too_many holes_fit
  | TooMuchData => exact fun too_much => too_much data_fits
  | Misplaced =>
    exact fun ⟨placed, misplaced⟩ =>
      have ⟨in_the_file, in_order, have_bytes, _⟩ := ranges placed
      misplaced ⟨in_the_file, in_order, have_bytes⟩
  | CompressedTooBig =>
    exact fun ⟨placed, too_big⟩ =>
      have ⟨_, _, _, within_bound⟩ := ranges placed
      too_big within_bound

/-- A good list is not refused (a refusal would name a false statement, and all are true), so it
is accepted. -/
theorem every_good_list_is_accepted : EveryGoodListIsAccepted :=
  fun file chunks caps before good =>
    WP.spec_mono (check_judges file chunks caps before) (fun answer judged => by
      cases answer with
      | Ok t => exact ⟨t, rfl⟩
      | Err why => exact absurd (judged.2 why rfl) (nothing_good_is_named file _ caps before good why))

/-- An accepted answer is `Accepted`; with `before` within the caps its totals are too, so the
list is `Good` (the parts are the same). -/
theorem accepted_is_good : AcceptedIsGood :=
  fun file chunks caps before zeros_within planned_within =>
    WP.spec_mono (check_judges file chunks caps before) (fun _ judged t answered =>
      have accepted := judged.1 t answered
      ⟨accepted.tiles, accepted.fits,
        by have := accepted.zeros_within zeros_within; have := accepted.zeros_sum
           unfold HolesFitTheCap; omega,
        by have := accepted.planned_within planned_within; have := accepted.planned_sum
           unfold DataFitsTheCap; omega,
        accepted.ranges⟩)

/-- A refusal is `Judged`: its second part is the claim. -/
theorem a_refusal_names_a_false_statement : ARefusalNamesAFalseStatement :=
  fun file chunks caps before =>
    WP.spec_mono (check_judges file chunks caps before)
      (fun _ judged why refused => judged.2 why refused)

/-- `Good` can be met, by a placed file that mixes data and holes (so `EveryGoodListIsAccepted`
is not about nothing): three chunks of a byte, data, hole, data, in a file of 3 bytes whose
compressed range is 20 bytes, the hole's range empty. -/
example : Good ⟨3#u64, 0#u64, 20#u64, true⟩
    [⟨0#u64, 1#u64, 0#u64, false⟩, ⟨1#u64, 1#u64, 10#u64, true⟩, ⟨2#u64, 1#u64, 10#u64, false⟩]
    ⟨1#u64, 1#u64, 2#u64⟩ ⟨0#u64, 0#u64⟩ := by
  refine ⟨?_, ?_, ?_, ?_, fun _ => ⟨?_, ?_, ?_, ?_⟩⟩
  · simp [Tiles, TilesFrom]
  · simp [DataChunksFitTheCap]
  · simp [HolesFitTheCap, HoleBytes]
  · simp [DataFitsTheCap, DataBytes]
  · intro j inside
    obtain rfl | rfl | rfl : j = 0 ∨ j = 1 ∨ j = 2 := by simp at inside; omega
    all_goals simp [CompEnd]
  · intro j k inside after
    obtain rfl | rfl | rfl : k = 0 ∨ k = 1 ∨ k = 2 := by simp at inside; omega
    all_goals obtain rfl | rfl : j = 0 ∨ j = 1 := by omega
    all_goals first | omega | simp [CompEnd]
  · intro j inside data
    obtain rfl | rfl | rfl : j = 0 ∨ j = 1 ∨ j = 2 := by simp at inside; omega
    all_goals simp_all [CompEnd]
  · intro j inside data
    obtain rfl | rfl | rfl : j = 0 ∨ j = 1 ∨ j = 2 := by simp at inside; omega
    all_goals simp_all [CompEnd, CompressedBoundOf]

end ChunkCore
