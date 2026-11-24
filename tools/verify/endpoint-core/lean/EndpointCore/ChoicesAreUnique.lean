-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: that `Chooses` of Spec.lean names one block at most: two blocks (or two
-- `none`) chosen for the same name among the same blocks are the same.
-- Why it is needed: `endpoints` asks `select` for the block of the name and for the block of the
-- address of each mirror; the claims say what the chosen block is, so what `select` found must
-- be the block the claims speak of.
-- Read before this file: Spec.lean.
-- Notation: `blocks[b]?` is `some` of the block at the place `b` of `blocks`, or `none`.
import EndpointCore.Spec

open Aeneas Aeneas.Std Result velarx_endpoint_core

namespace EndpointCore

/-- Only one block is chosen: if `one` and `other` are both chosen for a name among `blocks`, they
are the same. -/
theorem a_choice_is_unique (blocks : List Block) (ref : Bytes) (one other : Option Nat)
    (is_one : Chooses blocks ref one) (is_other : Chooses blocks ref other) : one = other := by
  rcases one with _ | b
  · rcases other with _ | c
    · rfl
    · obtain ⟨block, at_c, nonempty, governs, _⟩ := is_other.1 c rfl
      exact absurd governs ((is_one.2.mp rfl) block (List.mem_of_getElem? at_c) nonempty)
  · obtain ⟨block, at_b, nonempty, governs, longest, first⟩ := is_one.1 b rfl
    rcases other with _ | c
    · exact absurd governs ((is_other.2.mp rfl) block (List.mem_of_getElem? at_b) nonempty)
    · obtain ⟨block', at_c, nonempty', governs', longest', first'⟩ := is_other.1 c rfl
      have b_at_most := longest block' (List.mem_of_getElem? at_c) nonempty' governs'
      have c_at_most := longest' block (List.mem_of_getElem? at_b) nonempty governs
      have same_length : block.prefix.length = block'.prefix.length := by omega
      rcases Nat.lt_trichotomy b c with before | same | after
      · have := first' b block before at_b nonempty governs
        omega
      · rw [same]
      · have := first c block' after at_c nonempty' governs'
        omega

end EndpointCore
