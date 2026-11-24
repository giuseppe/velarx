-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the first loop of `check` (crates/chunk-core): it reads the chunks one by
-- one, keeps in `tiled` the bytes they tile and in `totals` the holes and the data it has seen, and
-- stops at the first chunk that does not tile, or is over a cap.  `walk_the_chunks` says what it
-- returns: if it has not refused, the chunks tile the first `tiled` bytes and the totals are
-- `before` plus their holes and data; if it has refused, the refusal names a statement that is
-- false of the whole list.
--
-- Why it is needed: this loop is where `check` decides the tiling and the caps, which are most
-- of the claims of Spec.lean.  Each turn keeps `Outcome`, the invariant, and the facts before the
-- loop (`not_tiled_at`, `too_many_zeros_at`, `too_much_data_at`, `counted_after_a_hole`,
-- `counted_after_data`) say what one chunk adds to it.
--
-- Read before this file: Spec.lean, Tiling.lean, Sums.lean, CheckedSums.lean, and the first loop of
-- `check` in src/lib.rs.
--
-- Notation: `x ⦃ r => P r ⦄` is "the function returns, and its result `r` satisfies `P r`";
-- `r.1`, `r.2.1`, ... are the parts of the tuple a loop returns (its file, totals, refusal and
-- tiled bytes); `loop.spec_decr_nat` proves that a loop returns because a number goes down at each
-- turn (here, the chunks not yet read) and a fact (the invariant) is kept by each turn; `split`
-- makes one case of each `if`; `step as ⟨ x, hx ⟩` runs one Rust line and names its result `x` and
-- what is known of it `hx`; `scalar_tac` decides facts about machine integers.
import ChunkCore.Tiling
import ChunkCore.Sums
import ChunkCore.CheckedSums

open Aeneas Aeneas.Std Result velarx_chunk_core

namespace ChunkCore

/-- The first `k` chunks tile the file up to `tiled` (the variable `tiled` of the loop), which is
within the file. -/
def Tiled (file : File) (chunks : List Chunk) (k : Nat) (tiled : Std.U64) : Prop :=
  TilesFrom (chunks.take k) 0 tiled.val ∧ tiled.val ≤ file.size.val

/-- What the totals of the loop are after the first `k` chunks: `before` plus their holes and their
data; each total is within its cap if the one before was (so the holes and the data of the file
fit when `before` does); and no chunk of data of the first `k` is over the cap of a chunk. -/
def Counted (caps : Caps) (before : Totals) (chunks : List Chunk) (k : Nat)
    (totals : Totals) : Prop :=
  totals.zeros.val = before.zeros.val + HoleBytes (chunks.take k) ∧
  totals.planned.val = before.planned.val + DataBytes (chunks.take k) ∧
  (before.zeros.val ≤ caps.zeros.val → totals.zeros.val ≤ caps.zeros.val) ∧
  (before.planned.val ≤ caps.planned.val → totals.planned.val ≤ caps.planned.val) ∧
  DataChunksFitTheCap caps (chunks.take k)

/-- What the loop knows at the turn of the chunk `k`: if it has not refused, the chunks before `k`
are tiled and counted; if it has refused, the refusal names a false statement of the whole input. -/
def Outcome (file : File) (chunks : List Chunk) (caps : Caps) (before : Totals) (k : Nat)
    (totals : Totals) (refusal : Option Refusal) (tiled : Std.U64) : Prop :=
  match refusal with
  | none => Tiled file chunks k tiled ∧ Counted caps before chunks k totals
  | some why => Named why file chunks caps before

/-- `is_none` of no refusal is true (the loop goes on while this is so). -/
theorem is_none_none : core.option.Option.is_none (none : Option Refusal) = true := rfl

/-- A chunk that does not begin where the ones before it end, or has no byte, or is longer than the
bytes left, shows that the chunks do not tile the file: if they did, the chunks before it would
tile up to where it begins (`tiles_next_chunk`). -/
theorem not_tiled_at (file : File) (chunks : List Chunk) (k : Nat) (tiled : Std.U64)
    (c : Chunk) (inside : k < chunks.length) (is_chunk : chunks[k] = c)
    (tiled_k : Tiled file chunks k tiled)
    (bad : c.file_off.val ≠ tiled.val ∨ c.size.val = 0 ∨ file.size.val - tiled.val < c.size.val) :
    Named .NotTiled file chunks caps before := by
  intro tiles
  obtain ⟨begins, has_bytes, fits⟩ :=
    tiles_next_chunk chunks 0 tiled.val file.size.val k tiles tiled_k.1 inside
  rw [is_chunk] at begins has_bytes fits
  have := tiled_k.2
  omega

/-- A hole that takes the holes past the cap shows that the holes of the whole list do too: the
holes of the first `k + 1` chunks are no more than the holes of the list. -/
theorem too_many_zeros_at (caps : Caps) (before : Totals) (chunks : List Chunk) (k : Nat)
    (totals : Totals) (c : Chunk) (inside : k < chunks.length) (is_chunk : chunks[k] = c)
    (counted : Counted caps before chunks k totals) (hole : c.zeros = true)
    (over : caps.zeros.val < totals.zeros.val + c.size.val) :
    ¬ HolesFitTheCap caps before chunks := by
  intro fits
  have next := (bytes_after_a_hole (chunks.take k) c hole).1
  have all := hole_bytes_of_the_first_are_at_most chunks (k + 1)
  rw [take_one_more chunks k inside, is_chunk, next] at all
  have := counted.1
  unfold HolesFitTheCap at fits
  omega

/-- A chunk of data that takes the data past the cap shows that the data of the whole list is
past it: the data of the first `k + 1` chunks is no more than the data of the list. -/
theorem too_much_data_at (caps : Caps) (before : Totals) (chunks : List Chunk) (k : Nat)
    (totals : Totals) (c : Chunk) (inside : k < chunks.length) (is_chunk : chunks[k] = c)
    (counted : Counted caps before chunks k totals) (data : c.zeros = false)
    (over : caps.planned.val < totals.planned.val + c.size.val) :
    ¬ DataFitsTheCap caps before chunks := by
  intro fits
  have next := (bytes_after_data (chunks.take k) c data).2
  have all := data_bytes_of_the_first_are_at_most chunks (k + 1)
  rw [take_one_more chunks k inside, is_chunk, next] at all
  have := counted.2.1
  unfold DataFitsTheCap at fits
  omega

/-- Taking one more chunk, a hole that fits the cap, keeps `Counted`: the sum of the holes is the new
total, and the data is as before. -/
theorem counted_after_a_hole (caps : Caps) (before : Totals) (chunks : List Chunk) (k : Nat)
    (totals : Totals) (c : Chunk) (inside : k < chunks.length) (is_chunk : chunks[k] = c)
    (counted : Counted caps before chunks k totals) (hole : c.zeros = true)
    (sum : Std.U64) (is_sum : sum.val = totals.zeros.val + c.size.val)
    (within_cap : sum.val ≤ caps.zeros.val) :
    Counted caps before chunks (k + 1) ⟨sum, totals.planned⟩ := by
  obtain ⟨zeros, planned, zeros_fit, planned_fit, chunks_fit⟩ := counted
  have next := bytes_after_a_hole (chunks.take k) c hole
  unfold Counted
  rw [take_one_more chunks k inside, is_chunk]
  refine ⟨by simp only; omega, by simp only; omega, fun _ => within_cap, planned_fit, ?_⟩
  exact fit_the_cap_one_more caps _ c chunks_fit (by simp [hole])

/-- Taking one more chunk, a chunk of data that is within the cap of a chunk and keeps the data
within its cap, keeps `Counted`: the sum of the data is the new total, and the holes are as
before. -/
theorem counted_after_data (caps : Caps) (before : Totals) (chunks : List Chunk) (k : Nat)
    (totals : Totals) (c : Chunk) (inside : k < chunks.length) (is_chunk : chunks[k] = c)
    (counted : Counted caps before chunks k totals) (data : c.zeros = false)
    (small : c.size.val ≤ caps.chunk.val)
    (sum : Std.U64) (is_sum : sum.val = totals.planned.val + c.size.val)
    (within_cap : sum.val ≤ caps.planned.val) :
    Counted caps before chunks (k + 1) ⟨totals.zeros, sum⟩ := by
  obtain ⟨zeros, planned, zeros_fit, planned_fit, chunks_fit⟩ := counted
  have next := bytes_after_data (chunks.take k) c data
  unfold Counted
  rw [take_one_more chunks k inside, is_chunk]
  refine ⟨by simp only; omega, by simp only; omega, zeros_fit, fun _ => within_cap, ?_⟩
  exact fit_the_cap_one_more caps _ c chunks_fit (fun _ => small)

/-- The first loop of `check` returns, and its answer is `Outcome` for the whole list: either
every chunk is tiled and counted, or the refusal it holds names a false statement.  One turn of
the loop reads one chunk, and a chunk is refused for the first of these that is so: it is not
where the tiling is, it has no byte, it is longer than the bytes left, it is a hole that takes the
holes past their cap, it is a chunk of data over the cap of a chunk, or it takes the data past
its cap. -/
theorem walk_the_chunks (file : File) (chunks : Slice Chunk) (caps : Caps) (before : Totals) :
    check_loop0 file chunks caps before none 0#u64 0#usize ⦃ r =>
      r.1 = file ∧
      Outcome file chunks.val caps before chunks.val.length r.2.1 r.2.2.1 r.2.2.2 ⦄ := by
  unfold check_loop0
  apply loop.spec_decr_nat (fun q => chunks.length - q.2.2.2.2.2.val)
    (fun q => q.1 = file ∧ q.2.1 = caps ∧ q.2.2.2.2.2.val ≤ chunks.length ∧
      Outcome file chunks.val caps before q.2.2.2.2.2.val q.2.2.1 q.2.2.2.1 q.2.2.2.2.1)
  · rintro ⟨file1, caps1, totals, refusal, tiled, j⟩ ⟨rfl, rfl, read, outcome⟩
    simp only at read outcome ⊢
    unfold check_loop0.body
    dsimp only [Slice.len]
    split
    · rename_i below
      have below : j.val < chunks.length := by scalar_tac
      split
      · rename_i unrefused
        have unrefused : refusal = none := by cases refusal <;> simp_all
        subst unrefused
        obtain ⟨tiled_j, counted_j⟩ := outcome
        -- the chunk `j` is read
        step as ⟨ c, hc ⟩
        have is_chunk : chunks.val[j.val] = c := hc.symm
        refine WP.spec_bind (Pₘ := fun r => r.1 = file1 ∧ r.2.1 = caps1 ∧
          match r.2.2.2 with
          | none => c.file_off.val = tiled.val ∧ 0 < c.size.val ∧
              c.size.val ≤ file1.size.val - tiled.val ∧
              Counted caps1 before chunks.val (j.val + 1) r.2.2.1
          | some why => Named why file1 chunks.val caps1 before) ?_ ?_
        · -- the chunk is judged: it does not tile, or it is a hole, or it is data
          split
          · -- it does not begin where the chunks before it end
            rename_i wrong_place
            have wrong_place : c.file_off.val ≠ tiled.val := fun same =>
              by simp [UScalar.eq_of_val_eq same] at wrong_place
            exact (WP.spec_ok _).mpr ⟨rfl, rfl, not_tiled_at file1 chunks.val j.val tiled c below
              is_chunk tiled_j (Or.inl wrong_place)⟩
          · rename_i right_place
            have right_place : c.file_off.val = tiled.val := by
              simpa using right_place
            -- it has no byte
            split
            · rename_i empty
              have empty : c.size.val = 0 := by simpa using congrArg UScalar.val empty
              exact (WP.spec_ok _).mpr ⟨rfl, rfl, not_tiled_at file1 chunks.val j.val tiled c below
                is_chunk tiled_j (Or.inr (Or.inl empty))⟩
            · rename_i has_bytes
              have has_bytes : 0 < c.size.val := by
                have : c.size.val ≠ 0 := fun zero => has_bytes (UScalar.eq_of_val_eq zero)
                omega
              -- it is longer than the bytes left in the file
              step as ⟨ room, hroom ⟩
              split
              · rename_i too_long
                have too_long : file1.size.val - tiled.val < c.size.val := by
                  scalar_tac
                simp only [Std.bind_ok]
                exact (WP.spec_ok _).mpr ⟨rfl, rfl, not_tiled_at file1 chunks.val j.val tiled c
                  below is_chunk tiled_j (Or.inr (Or.inr too_long))⟩
              · rename_i fits
                have fits : c.size.val ≤ file1.size.val - tiled.val := by
                  scalar_tac
                -- the sums are checked: a hole against the cap of the holes, data against its
                -- own cap and the cap of the data
                split
                · rename_i hole
                  step as ⟨ o2, within_cap, over_cap ⟩
                  cases o2 with
                  | none =>
                    simp only [Std.bind_ok, Std.uncurry_apply_pair]
                    exact (WP.spec_ok _).mpr ⟨rfl, rfl, too_many_zeros_at caps1 before chunks.val
                      j.val totals c below is_chunk counted_j hole (over_cap rfl)⟩
                  | some sum =>
                    simp only [Std.bind_ok, Std.uncurry_apply_pair]
                    obtain ⟨is_sum, within_cap⟩ := within_cap sum rfl
                    exact (WP.spec_ok _).mpr ⟨rfl, rfl, right_place, has_bytes, fits,
                      counted_after_a_hole caps1 before chunks.val j.val totals c below is_chunk
                        counted_j hole sum is_sum within_cap⟩
                · rename_i data
                  have data : c.zeros = false := by simpa using data
                  split
                  · rename_i too_big
                    have too_big : caps1.chunk.val < c.size.val := by scalar_tac
                    simp only [Std.bind_ok, Std.uncurry_apply_pair]
                    exact (WP.spec_ok _).mpr ⟨rfl, rfl, a_chunk_over_the_cap caps1 chunks.val j.val
                      below (by rw [is_chunk]; exact data) (by rw [is_chunk]; exact too_big)⟩
                  · rename_i small
                    have small : c.size.val ≤ caps1.chunk.val := by scalar_tac
                    step as ⟨ o2, within_cap, over_cap ⟩
                    cases o2 with
                    | none =>
                      simp only [Std.bind_ok, Std.uncurry_apply_pair]
                      exact (WP.spec_ok _).mpr ⟨rfl, rfl, too_much_data_at caps1 before chunks.val
                        j.val totals c below is_chunk counted_j data (over_cap rfl)⟩
                    | some sum =>
                      simp only [Std.bind_ok, Std.uncurry_apply_pair]
                      obtain ⟨is_sum, within_cap⟩ := within_cap sum rfl
                      exact (WP.spec_ok _).mpr ⟨rfl, rfl, right_place, has_bytes, fits,
                        counted_after_data caps1 before chunks.val j.val totals c below is_chunk
                          counted_j data small sum is_sum within_cap⟩
        · -- the next turn: the chunk is tiled and counted, or the loop holds a refusal
          rintro ⟨file2, caps2, totals2, refusal2⟩ ⟨rfl, rfl, judged⟩
          simp only [Std.uncurry_apply_pair] at judged tiled_j counted_j ⊢
          cases refusal2 with
          | none =>
            simp only [Option.isNone_none, ↓reduceIte]
            obtain ⟨right_place, has_bytes, fits, counted_next⟩ := judged
            step as ⟨ tiled1, htiled1 ⟩
            step as ⟨ j1, hj1 ⟩
            have tiles_next : Tiled file2 chunks.val (j.val + 1) tiled1 := by
              refine ⟨?_, by have := tiled_j.2; omega⟩
              rw [take_one_more chunks.val j.val below, is_chunk, htiled1]
              exact tiles_one_more _ _ _ _ tiled_j.1 right_place has_bytes
            rw [hj1]
            exact ⟨by omega, ⟨tiles_next, counted_next⟩, by omega⟩
          | some why =>
            simp only [Option.isNone_some, Bool.false_eq_true, ↓reduceIte, Std.bind_ok]
            step as ⟨ j1, hj1 ⟩
            rw [hj1]
            exact ⟨by omega, judged, by omega⟩
      · -- a refusal is held: the loop ends with it
        rename_i refused
        cases refusal with
        | none => exact absurd is_none_none (by simp at refused)
        | some why => exact (WP.spec_ok _).mpr ⟨rfl, outcome⟩
    · -- every chunk was read
      have : j.val = chunks.length := by scalar_tac
      rw [this] at outcome
      exact (WP.spec_ok _).mpr ⟨rfl, outcome⟩
  · -- before the first chunk, nothing is tiled and nothing is counted
    refine ⟨rfl, rfl, by simp, ⟨by simp [TilesFrom], by simp⟩, ?_⟩
    exact ⟨by simp [HoleBytes], by simp [DataBytes], fun h => h, fun h => h,
      by simp [DataChunksFitTheCap]⟩
