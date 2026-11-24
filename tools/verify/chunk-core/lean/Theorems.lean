-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the list of what is proved of crates/chunk-core.  The statements are in
-- ChunkCore/Spec.lean, the proofs in ChunkCore/Claims.lean (which uses the files before it in
-- ChunkCore/).
-- ../../run ends on this file: it fails unless every line `#proved T` below
-- prints "proved: T".
--
-- Why it is needed: Lean checks a proof when it is read, but nothing
-- says that the theorem is the one of the statement or that no `sorry`
-- or new axiom is behind it.  `#proved T` (../../Proved.lean) prints the
-- axioms `T` rests on and fails unless they are the three of Lean and the
-- library functions the crate has no model of (the run prints none for this crate).
--
-- Read before this file: ChunkCore/Spec.lean.
import Proved
import ChunkCore.Claims

-- Each theorem is a proof of the statement of that name in Spec.lean: Lean
-- checks the type of each line below, so Theorems.lean and Spec.lean suffice.
example : ChunkCore.CompressedBoundIsTheFormula :=
  ChunkCore.compressed_bound_is_the_formula
example : ChunkCore.CompRangeIsTheRangeOfTheChunk :=
  ChunkCore.comp_range_is_the_range_of_the_chunk
example : ChunkCore.CheckAlwaysReturns :=
  ChunkCore.check_always_returns
example : ChunkCore.AcceptedChunksTileTheFile :=
  ChunkCore.accepted_chunks_tile_the_file
example : ChunkCore.AcceptedDataChunksFitTheCap :=
  ChunkCore.accepted_data_chunks_fit_the_cap
example : ChunkCore.AcceptedTotalsAreTheSums :=
  ChunkCore.accepted_totals_are_the_sums
example : ChunkCore.AcceptedTotalsAreWithinTheCaps :=
  ChunkCore.accepted_totals_are_within_the_caps
example : ChunkCore.AcceptedRangesAreInTheFileInOrder :=
  ChunkCore.accepted_ranges_are_in_the_file_in_order
example : ChunkCore.AcceptedDataRangesHaveBytesWithinTheBound :=
  ChunkCore.accepted_data_ranges_have_bytes_within_the_bound
example : ChunkCore.AcceptedIsGood :=
  ChunkCore.accepted_is_good
example : ChunkCore.EveryGoodListIsAccepted :=
  ChunkCore.every_good_list_is_accepted
example : ChunkCore.ARefusalNamesAFalseStatement :=
  ChunkCore.a_refusal_names_a_false_statement

#proved ChunkCore.compressed_bound_is_the_formula
#proved ChunkCore.comp_range_is_the_range_of_the_chunk
#proved ChunkCore.check_always_returns
#proved ChunkCore.accepted_chunks_tile_the_file
#proved ChunkCore.accepted_data_chunks_fit_the_cap
#proved ChunkCore.accepted_totals_are_the_sums
#proved ChunkCore.accepted_totals_are_within_the_caps
#proved ChunkCore.accepted_ranges_are_in_the_file_in_order
#proved ChunkCore.accepted_data_ranges_have_bytes_within_the_bound
#proved ChunkCore.accepted_is_good
#proved ChunkCore.every_good_list_is_accepted
#proved ChunkCore.a_refusal_names_a_false_statement
