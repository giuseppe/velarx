-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: how the block chosen (`Chooses` of Spec.lean) changes when one more block
-- is looked at after the others: a block that governs the name and has a longer prefix than the
-- best one so far becomes the choice, and any other block changes nothing.  Before any block,
-- nothing is chosen.
-- Why it is needed: `select` looks at the blocks one by one and keeps the best so far; this is
-- the step of its loop, said without the code.
-- Read before this file: Spec.lean.
-- Notation: `L ++ [x]` is the list `L` with `x` added at the end; `L[b]?` is `some` of the element
-- at the place `b` of `L`, or `none`.
import EndpointCore.Spec

open Aeneas Aeneas.Std Result velarx_endpoint_core

namespace EndpointCore

/-- `best_len` is the length of the prefix of the block `best` of `blocks` (0 for none). -/
def LengthIs (blocks : List Block) (best : Option Nat) (best_len : Nat) : Prop :=
  (best = none → best_len = 0) ∧
    ∀ b, best = some b → ∃ block, blocks[b]? = some block ∧ block.prefix.length = best_len

/-- With no block looked at, no block is chosen. -/
theorem nothing_is_chosen_from_no_blocks (ref : Bytes) : Chooses [] ref none := by
  refine ⟨by simp, ?_⟩
  simp

/-- A governing block with a prefix longer than the best so far is the choice among the blocks
looked at so far and it. -/
theorem a_longer_governing_prefix_wins (blocks : List Block) (ref : Bytes) (best : Option Nat)
    (best_len : Nat) (chosen : Chooses blocks ref best) (length_is : LengthIs blocks best best_len)
    (x : Block) (governs : Governs x.prefix.val ref) (longer : best_len < x.prefix.length) :
    Chooses (blocks ++ [x]) ref (some blocks.length) := by
  have nonempty : x.prefix.val ≠ [] := by
    intro empty
    simp [alloc.vec.Vec.length, empty] at longer
  have below_best : ∀ other ∈ blocks, other.prefix.val ≠ [] → Governs other.prefix.val ref →
      other.prefix.length ≤ best_len := by
    intro other other_in other_nonempty other_governs
    rcases best with _ | b
    · exact absurd other_governs ((chosen.2.mp rfl) other other_in other_nonempty)
    · obtain ⟨block, at_b, _, _, is_longest, _⟩ := chosen.1 b rfl
      obtain ⟨block', at_b', len_is⟩ := length_is.2 b rfl
      rw [at_b] at at_b'
      cases at_b'
      rw [← len_is]
      exact is_longest other other_in other_nonempty other_governs
  refine ⟨?_, ?_⟩
  · intro b is_b
    cases is_b
    refine ⟨x, by simp, nonempty, governs, ?_, ?_⟩
    · intro other other_in other_nonempty other_governs
      rcases List.mem_append.mp other_in with before | here
      · have := below_best other before other_nonempty other_governs
        omega
      · rw [List.mem_singleton.mp here]
    · intro j earlier j_before at_j earlier_nonempty earlier_governs
      have in_blocks : blocks[j]? = some earlier := by
        rw [List.getElem?_append_left j_before] at at_j
        exact at_j
      have := below_best earlier (List.mem_of_getElem? in_blocks) earlier_nonempty earlier_governs
      omega
  · constructor
    · intro none
      cases none
    · intro all_not
      exact absurd governs (all_not x (by simp) nonempty)

/-- A block that does not both govern the name and have a prefix longer than the best so far
leaves the choice as it was. -/
theorem any_other_block_changes_nothing (blocks : List Block) (ref : Bytes) (best : Option Nat)
    (best_len : Nat) (chosen : Chooses blocks ref best) (length_is : LengthIs blocks best best_len)
    (x : Block) (no_win : ¬ (best_len < x.prefix.length ∧ Governs x.prefix.val ref)) :
    Chooses (blocks ++ [x]) ref best := by
  have x_not_longer :
      x.prefix.val ≠ [] → Governs x.prefix.val ref → x.prefix.length ≤ best_len := by
    intro _ governs
    by_contra longer
    exact no_win ⟨by omega, governs⟩
  refine ⟨?_, ?_⟩
  · intro b is_b
    obtain ⟨block, at_b, nonempty, governs, longest, first⟩ := chosen.1 b is_b
    have inside : b < blocks.length := (List.getElem?_eq_some_iff.mp at_b).1
    obtain ⟨block', at_b', len_is⟩ := length_is.2 b is_b
    rw [at_b] at at_b'
    cases at_b'
    refine ⟨block, by rw [List.getElem?_append_left inside]; exact at_b, nonempty, governs, ?_, ?_⟩
    · intro other other_in other_nonempty other_governs
      rcases List.mem_append.mp other_in with before | here
      · exact longest other before other_nonempty other_governs
      · rw [List.mem_singleton.mp here] at other_nonempty other_governs ⊢
        rw [← len_is] at x_not_longer
        exact x_not_longer other_nonempty other_governs
    · intro j earlier j_before at_j earlier_nonempty earlier_governs
      have in_blocks : blocks[j]? = some earlier := by
        rw [List.getElem?_append_left (by omega)] at at_j
        exact at_j
      exact first j earlier j_before in_blocks earlier_nonempty earlier_governs
  · constructor
    · intro is_none
      have all_not := chosen.2.mp is_none
      have zero := length_is.1 is_none
      intro other other_in other_nonempty other_governs
      rcases List.mem_append.mp other_in with before | here
      · exact all_not other before other_nonempty other_governs
      · rw [List.mem_singleton.mp here] at other_nonempty other_governs
        have := x_not_longer other_nonempty other_governs
        have : 0 < x.prefix.length := by
          cases h : x.prefix.val with
          | nil => exact absurd h other_nonempty
          | cons _ _ => simp [alloc.vec.Vec.length, h]
        omega
    · intro all_not
      exact chosen.2.mpr fun other other_in => all_not other (List.mem_append_left _ other_in)

/-- After a winner is added, the length it was kept with is the length of its prefix. -/
theorem the_winner_has_its_length (blocks : List Block) (x : Block) :
    LengthIs (blocks ++ [x]) (some blocks.length) x.prefix.length :=
  ⟨fun is_none => by simp at is_none, fun b is_b => ⟨x, by
    cases is_b
    simp, rfl⟩⟩

/-- When a block is added that does not win, the length that was kept stays the length of the
prefix of the block kept. -/
theorem the_length_stays (blocks : List Block) (best : Option Nat) (best_len : Nat)
    (length_is : LengthIs blocks best best_len) (x : Block) :
    LengthIs (blocks ++ [x]) best best_len := by
  refine ⟨length_is.1, fun b is_b => ?_⟩
  obtain ⟨block, at_b, len_is⟩ := length_is.2 b is_b
  have inside : b < blocks.length := (List.getElem?_eq_some_iff.mp at_b).1
  exact ⟨block, by rw [List.getElem?_append_left inside]; exact at_b, len_is⟩

end EndpointCore
