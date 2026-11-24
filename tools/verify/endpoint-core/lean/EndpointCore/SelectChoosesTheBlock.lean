-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `select` returns the block chosen for the name (`Chooses` of Spec.lean):
-- the first of the blocks with the longest prefix that governs the name, and `none` when none
-- governs it (a block with an empty prefix is never chosen).  It always returns.
-- Why it is needed: `endpoints` asks `select` for the block of the name, and for the block that
-- governs the address of each mirror.
-- Read before this file: Spec.lean, GovernsMeansGoverns.lean, ExtendingTheChoice.lean.
-- Notation: `loop.spec_decr_nat` proves that a loop returns because a number goes down at each
-- turn while a fact (the invariant) is kept by each turn; `step as ⟨ x, hx ⟩` runs one line of a
-- Rust function and names its result `x` and what is known of it `hx`; `blocks.val.take i` is the
-- first `i` blocks.
import EndpointCore.Spec
import EndpointCore.GovernsMeansGoverns
import EndpointCore.ExtendingTheChoice
import EndpointCore.PrefixesOfLists

open Aeneas Aeneas.Std Result velarx_endpoint_core

namespace EndpointCore

/-- **`prefix_len`** is the length of the prefix of the block at the place `i`. -/
theorem prefix_len_is_the_length (blocks : Slice Block) (i : Std.Usize) (block : Block)
    (is_block : blocks.val[i.val]? = some block) :
    prefix_len blocks i ⦃ r => r.val = block.prefix.length ⦄ := by
  have inside : i.val < blocks.val.length := (List.getElem?_eq_some_iff.mp is_block).1
  unfold prefix_len
  step as ⟨ blk, is_blk ⟩
  have blk_is : blk = block := by
    have := List.getElem?_eq_getElem inside
    rw [is_block] at this
    simp [is_blk, Option.some.inj this]
  subst blk_is
  simp

/-- The loop of **`select`**: from the block `i`, with the best block so far and the length of its
prefix, it ends with the block chosen among all the blocks. -/
theorem select_loop_chooses (blocks : Slice Block) (ref : Slice Std.U8) (best : Option Std.Usize)
    (best_len i : Std.Usize) (inside : i.val ≤ blocks.length)
    (chosen : Chooses (blocks.val.take i.val) ref.val (best.map (·.val)))
    (length_is : LengthIs (blocks.val.take i.val) (best.map (·.val)) best_len.val) :
    select_loop blocks ref best best_len i ⦃ found =>
      Chooses blocks.val ref.val (found.map (·.val)) ⦄ := by
  unfold select_loop
  apply loop.spec_decr_nat
    (fun (q : Option Std.Usize × Std.Usize × Std.Usize) => blocks.length - q.2.2.val)
    (fun (q : Option Std.Usize × Std.Usize × Std.Usize) => q.2.2.val ≤ blocks.length ∧
      Chooses (blocks.val.take q.2.2.val) ref.val (q.1.map (·.val)) ∧
      LengthIs (blocks.val.take q.2.2.val) (q.1.map (·.val)) q.2.1.val)
  · rintro ⟨best, best_len, i⟩ ⟨inside, chosen, length_is⟩
    simp only at inside chosen length_is ⊢
    unfold select_loop.body
    have same_length : blocks.val.length = blocks.length := rfl
    by_cases below : i.val < blocks.length
    · have below' : i < Slice.len blocks := by scalar_tac
      simp only [below', ite_true]
      obtain ⟨block, is_block⟩ : ∃ block, blocks.val[i.val]? = some block :=
        ⟨_, List.getElem?_eq_getElem (by omega)⟩
      have grows : blocks.val.take (i.val + 1) = blocks.val.take i.val ++ [block] := by
        have := take_one_more blocks.val i.val (by omega)
        rw [this, List.getElem?_eq_getElem (by omega)] at *
        simp [Option.some.inj is_block]
      have before_length : (blocks.val.take i.val).length = i.val := by
        simp only [List.length_take]
        omega
      step with prefix_len_is_the_length blocks i block is_block as ⟨ len, is_len ⟩
      by_cases longer : len > best_len
      · simp only [longer, ite_true]
        step with governs_says blocks i ref block is_block as ⟨ does, does_says ⟩
        by_cases governing : does = true
        · simp only [governing, ite_true]
          step as ⟨ next, is_next ⟩
          have longer' : best_len.val < block.prefix.length := by scalar_tac
          refine ⟨by scalar_tac, ?_, ?_, by scalar_tac⟩
          · rw [is_next, grows]
            have := a_longer_governing_prefix_wins _ ref.val _ best_len.val chosen length_is
              block (does_says.mp governing) longer'
            rw [before_length] at this
            simpa using this
          · have winner := the_winner_has_its_length (blocks.val.take i.val) block
            rw [before_length] at winner
            rw [is_next, grows, is_len]
            simpa using winner
        · have not_governing : does = false := by simpa using governing
          simp only [not_governing, Bool.false_eq_true, ↓reduceIte]
          step as ⟨ next, is_next ⟩
          refine ⟨by scalar_tac, ?_, ?_, by scalar_tac⟩
          · rw [is_next, grows]
            exact any_other_block_changes_nothing _ ref.val _ best_len.val chosen length_is block
              (fun ⟨_, governs⟩ => governing (does_says.mpr governs))
          · rw [is_next, grows]
            exact the_length_stays _ _ _ length_is block
      · have not_longer : ¬ best_len.val < block.prefix.length := by
          have : ¬ best_len < len := by simpa using longer
          scalar_tac
        have not_longer' : ¬ len > best_len := longer
        simp only [not_longer', ↓reduceIte]
        step as ⟨ next, is_next ⟩
        refine ⟨by scalar_tac, ?_, ?_, by scalar_tac⟩
        · rw [is_next, grows]
          exact any_other_block_changes_nothing _ ref.val _ best_len.val chosen length_is block
            (fun ⟨longer, _⟩ => not_longer longer)
        · rw [is_next, grows]
          exact the_length_stays _ _ _ length_is block
    · have below' : ¬ i < Slice.len blocks := by scalar_tac
      simp only [below', ↓reduceIte]
      refine (WP.spec_ok _).mpr ?_
      have at_end : i.val = blocks.val.length := by scalar_tac
      rw [at_end, List.take_length] at chosen
      exact chosen
  · exact ⟨inside, chosen, length_is⟩

/-- **`select`** returns the block chosen for the name: of the blocks whose prefix governs it, the
first of those with the longest prefix, and `none` when no block governs it. -/
@[step] theorem select_chooses_the_block (blocks : Slice Block) (ref : Slice Std.U8) :
    select blocks ref ⦃ found => Chooses blocks.val ref.val (found.map (·.val)) ⦄ := by
  unfold select
  exact select_loop_chooses blocks ref none 0#usize 0#usize (by simp)
    (by simpa using nothing_is_chosen_from_no_blocks ref.val)
    (by simp [LengthIs])

end EndpointCore
