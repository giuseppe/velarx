-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the second loop of `check` (crates/chunk-core), for a file that is placed:
-- it reads the compressed range of each chunk (`comp_range`) and refuses the first that begins
-- before the range of the file, ends before it begins, is data with no byte, or is data over
-- the bound.  `walk_the_ranges` says what it returns: every range fits (`RangeFits`), or the
-- refusal names a statement that is false.
--
-- Why it is needed: this loop is where `check` decides the ranges, which are the other claims
-- of Spec.lean; Ranges.lean turns "every range fits" into the statements about all the ranges.
--
-- Read before this file: Spec.lean, Ranges.lean, WalkTheChunks.lean, and the second loop of
-- `check` in src/lib.rs.
--
-- Notation: as in WalkTheChunks.lean; `refine WP.spec_bind (Pₘ := P) ?_ ?_` is "the next Rust
-- line returns something that satisfies `P`, and then show the rest for each such result".
import ChunkCore.Ranges
import ChunkCore.WalkTheChunks

open Aeneas Aeneas.Std Result velarx_chunk_core

namespace ChunkCore

/-- A range that begins before the range of the file, or ends before it begins, is a statement of
`Named .Misplaced`: the ranges of the file are not all in it. -/
theorem misplaced_here (file : File) (chunks : List Chunk) (caps : Caps) (before : Totals)
    (j : Nat) (inside : j < chunks.length) (placed : file.placed = true)
    (bad : ¬ (file.comp_start.val ≤ chunks[j].comp_off.val ∧
      chunks[j].comp_off.val ≤ CompEnd file chunks j)) :
    Named .Misplaced file chunks caps before := by
  refine ⟨placed, fun ⟨in_the_file, _, _⟩ => bad ?_⟩
  have := in_the_file j inside
  exact ⟨this.1, this.2.1⟩

/-- A chunk of data whose range has no byte is a statement of `Named .Misplaced`. -/
theorem misplaced_empty_here (file : File) (chunks : List Chunk) (caps : Caps) (before : Totals)
    (j : Nat) (inside : j < chunks.length) (placed : file.placed = true)
    (data : chunks[j].zeros = false)
    (empty : ¬ chunks[j].comp_off.val < CompEnd file chunks j) :
    Named .Misplaced file chunks caps before :=
  ⟨placed, fun ⟨_, _, have_bytes⟩ => empty (have_bytes j inside data)⟩

/-- A chunk of data whose range is over the bound of its size is what `Named .CompressedTooBig`
says. -/
theorem too_big_here (file : File) (chunks : List Chunk) (caps : Caps) (before : Totals)
    (j : Nat) (inside : j < chunks.length) (placed : file.placed = true)
    (data : chunks[j].zeros = false)
    (over : chunks[j].comp_off.val + CompressedBoundOf chunks[j].size.val <
      CompEnd file chunks j) :
    Named .CompressedTooBig file chunks caps before :=
  ⟨placed, fun within => absurd (within j inside data) (by omega)⟩

/-- What the second loop knows at the turn of the chunk `k`: if it has not refused, every chunk
before `k` has its range fit (`RangeFits`); if it has refused, the refusal names a false
statement. -/
def Placing (file : File) (chunks : List Chunk) (caps : Caps) (before : Totals) (k : Nat)
    (refusal : Option Refusal) : Prop :=
  match refusal with
  | none => ∀ (j : Nat) (inside : j < chunks.length), j < k → RangeFits file chunks j inside
  | some why => Named why file chunks caps before

/-- The second loop of `check` returns (for a file that is placed), and its answer is `Placing` for
all the chunks: every range fits, or the refusal names a false statement.  A turn reads the
range of one chunk with `comp_range` and refuses it for the first of these: it begins before the
range of the file, it ends before it begins, it is a chunk of data with no byte, or it is a chunk
of data over the compressed bound of its size. -/
theorem walk_the_ranges (file : File) (chunks : Slice Chunk) (caps : Caps) (before : Totals)
    (placed : file.placed = true) :
    check_loop1 file.size file.comp_start file.comp_end file.placed chunks none 0#usize ⦃ refusal =>
      Placing file chunks.val caps before chunks.val.length refusal ⦄ := by
  unfold check_loop1
  apply loop.spec_decr_nat (fun q => chunks.length - q.2.val)
    (fun q => q.2.val ≤ chunks.length ∧ Placing file chunks.val caps before q.2.val q.1)
  · rintro ⟨refusal, j⟩ ⟨read, placing⟩
    simp only at read placing ⊢
    unfold check_loop1.body
    dsimp only [Slice.len]
    split
    · rename_i below
      have below : j.val < chunks.length := by scalar_tac
      split
      · rename_i unrefused
        have unrefused : refusal = none := by cases refusal <;> simp_all
        subst unrefused
        have same_file : (⟨file.size, file.comp_start, file.comp_end, file.placed⟩ : File) = file :=
          rfl
        rw [same_file]
        -- the range of the chunk `j`
        step as ⟨ from_, end_, is_from, is_end ⟩
        refine WP.spec_bind (Pₘ := fun refusal1 => match refusal1 with
          | none => RangeFits file chunks.val j.val below
          | some why => Named why file chunks.val caps before) ?_ ?_
        · split
          · -- it begins before the range of the file
            rename_i before_the_file
            have before_the_file : chunks.val[j.val].comp_off.val < file.comp_start.val := by
              scalar_tac
            exact (WP.spec_ok _).mpr (misplaced_here file chunks.val caps before j.val below
              placed (by omega))
          · rename_i not_before
            -- it ends before it begins
            split
            · rename_i backwards
              have backwards : CompEnd file chunks.val j.val < chunks.val[j.val].comp_off.val := by
                scalar_tac
              exact (WP.spec_ok _).mpr (misplaced_here file chunks.val caps before j.val below
                placed (by omega))
            · rename_i forwards
              -- a hole may have any range that is not backwards; data is looked at more
              step as ⟨ c, hc ⟩
              split
              · rename_i hole
                have hole : chunks.val[j.val].zeros = true := by rw [← hc]; exact hole
                refine (WP.spec_ok _).mpr ⟨by scalar_tac, by scalar_tac, fun data => ?_⟩
                rw [hole] at data
                exact absurd data (by simp)
              · rename_i data
                have data : chunks.val[j.val].zeros = false := by rw [← hc]; simpa using data
                -- data with no byte
                split
                · rename_i empty
                  have empty : ¬ chunks.val[j.val].comp_off.val < CompEnd file chunks.val j.val := by
                    scalar_tac
                  exact (WP.spec_ok _).mpr (misplaced_empty_here file chunks.val caps before j.val
                    below placed data empty)
                · rename_i not_empty
                  -- data: its range against the bound of its size
                  step as ⟨ length, hlength ⟩
                  step as ⟨ bound, hbound ⟩
                  have is_c : c.size = chunks.val[j.val].size := by rw [hc]
                  rw [is_c] at hbound
                  have limit : end_.val ≤ Std.U64.max := by scalar_tac
                  split
                  · rename_i too_long
                    have too_long : bound.val < length.val := by scalar_tac
                    exact (WP.spec_ok _).mpr (too_big_here file chunks.val caps before j.val below
                      placed data (by omega))
                  · rename_i not_too_long
                    have not_too_long : length.val ≤ bound.val := by scalar_tac
                    have not_before : file.comp_start.val ≤ chunks.val[j.val].comp_off.val := by
                      scalar_tac
                    have not_backwards : chunks.val[j.val].comp_off.val ≤ CompEnd file chunks.val j.val := by
                      scalar_tac
                    have not_empty : chunks.val[j.val].comp_off.val ≠ CompEnd file chunks.val j.val := by
                      scalar_tac
                    refine (WP.spec_ok _).mpr ⟨not_before, not_backwards, fun _ => ⟨by omega, by omega⟩⟩
        · -- the next turn
          rintro refusal1 judged
          step as ⟨ j1, hj1 ⟩
          refine ⟨by omega, ?_, by omega⟩
          cases refusal1 with
          | some why => exact judged
          | none =>
            intro i inside before_next
            by_cases here : i = j.val
            · subst here
              exact judged
            · exact placing i inside (by omega)
      · -- a refusal is held: the loop ends with it
        rename_i refused
        cases refusal with
        | none => exact absurd rfl refused
        | some why => exact (WP.spec_ok _).mpr placing
    · -- every chunk was read
      have : j.val = chunks.length := by scalar_tac
      rw [this] at placing
      exact (WP.spec_ok _).mpr placing
  · exact ⟨by simp, fun j inside before_the_start => absurd before_the_start (by simp)⟩

end ChunkCore
