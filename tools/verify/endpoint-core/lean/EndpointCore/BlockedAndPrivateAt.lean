-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `blocked` and `allows_private` answer for the block that `select`
-- chose for an address: `blocked` is `true` exactly when the block chosen for the address is
-- blocked (`BlockedAt` of Spec.lean), and `allows_private` exactly when it lets its endpoints
-- reach private addresses (`AllowsPrivateAt`).
-- Why it is needed: `endpoints` asks for the block chosen for the address of each mirror, to skip
-- a mirror that is blocked and to let it reach private addresses when its own block does.
-- Read before this file: Spec.lean, ChoicesAreUnique.lean.
-- Notation: `found.map (·.val)` is the place of the block found, as a number.
import EndpointCore.Spec
import EndpointCore.ChoicesAreUnique

open Aeneas Aeneas.Std Result velarx_endpoint_core

namespace EndpointCore

/-- **`blocked`** says whether the block chosen for the address is blocked. -/
theorem blocked_says_the_block_is_blocked (blocks : Slice Block) (found : Option Std.Usize)
    (address : Bytes) (chosen : Chooses blocks.val address (found.map (·.val))) :
    blocked blocks found ⦃ r => r = true ↔ BlockedAt blocks.val address ⦄ := by
  unfold blocked
  cases found with
  | none =>
    simp only
    refine (WP.spec_ok _).mpr ?_
    simp only [Bool.false_eq_true, false_iff]
    rintro ⟨b, block, chosen_b, _⟩
    have := a_choice_is_unique _ _ _ _ chosen chosen_b
    simp at this
  | some b =>
    simp only
    obtain ⟨block, at_b, _⟩ := chosen.1 b.val (by simp)
    have inside : b.val < blocks.val.length := (List.getElem?_eq_some_iff.mp at_b).1
    step as ⟨ blk, is_blk ⟩
    have blk_is : blk = block := by
      have := List.getElem?_eq_getElem inside
      rw [at_b] at this
      simp [is_blk, Option.some.inj this]
    subst blk_is
    constructor
    · intro is_blocked
      exact ⟨b.val, blk, by simpa using chosen, at_b, is_blocked⟩
    · rintro ⟨c, block', chosen_c, at_c, is_blocked⟩
      have same := a_choice_is_unique _ _ _ _ chosen chosen_c
      simp only [Option.map_some, Option.some.injEq] at same
      rw [same] at at_b
      rw [at_b] at at_c
      cases at_c
      exact is_blocked

/-- **`allows_private`** says whether the block chosen for the address lets its endpoints reach
private addresses. -/
theorem allows_private_says_the_block_allows_it (blocks : Slice Block) (found : Option Std.Usize)
    (address : Bytes) (chosen : Chooses blocks.val address (found.map (·.val))) :
    allows_private blocks found ⦃ r => r = true ↔ AllowsPrivateAt blocks.val address ⦄ := by
  unfold allows_private
  cases found with
  | none =>
    simp only
    refine (WP.spec_ok _).mpr ?_
    simp only [Bool.false_eq_true, false_iff]
    rintro ⟨b, block, chosen_b, _⟩
    have := a_choice_is_unique _ _ _ _ chosen chosen_b
    simp at this
  | some b =>
    simp only
    obtain ⟨block, at_b, _⟩ := chosen.1 b.val (by simp)
    have inside : b.val < blocks.val.length := (List.getElem?_eq_some_iff.mp at_b).1
    step as ⟨ blk, is_blk ⟩
    have blk_is : blk = block := by
      have := List.getElem?_eq_getElem inside
      rw [at_b] at this
      simp [is_blk, Option.some.inj this]
    subst blk_is
    constructor
    · intro allows
      exact ⟨b.val, blk, by simpa using chosen, at_b, allows⟩
    · rintro ⟨c, block', chosen_c, at_c, allows⟩
      have same := a_choice_is_unique _ _ _ _ chosen chosen_c
      simp only [Option.map_some, Option.some.injEq] at same
      rw [same] at at_b
      rw [at_b] at at_c
      cases at_c
      exact allows

end EndpointCore
