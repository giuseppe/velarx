-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the claims of Spec.lean about `select` and about the
-- return of `select` and `endpoints`: `select_returns_the_block_chosen`,
-- `no_block_is_chosen_without_a_boundary` and `select_and_endpoints_always_return`.
-- Why it is needed: Theorems.lean ties each claim of Spec.lean to a proof, and these are the
-- proofs, each a short step from what the other files show.
-- Read before this file: Spec.lean, SelectChoosesTheBlock.lean, TheAnswerOfEndpoints.lean.
-- Notation: `WP.spec_mono h ?_` is "use the result `h` about the function, and show that what it
-- says is enough".
import EndpointCore.Spec
import EndpointCore.SelectChoosesTheBlock
import EndpointCore.TheAnswerOfEndpoints
import EndpointCore.FactsOfPairedLists

open Aeneas Aeneas.Std Result velarx_endpoint_core

namespace EndpointCore

theorem select_returns_the_block_chosen : SelectReturnsTheBlockChosen :=
  fun blocks ref => select_chooses_the_block blocks ref

theorem no_block_is_chosen_without_a_boundary : NoBlockIsChosenWithoutABoundary := by
  intro blocks ref
  refine WP.spec_mono (select_chooses_the_block blocks ref) ?_
  intro found chosen b is_b block at_block plain c rest split
  rw [is_b, Option.map_some] at chosen
  obtain ⟨block', at_block', _, governs, _⟩ := chosen.1 b.val rfl
  rw [at_block] at at_block'
  cases at_block'
  rcases governs with ⟨wild, _⟩ | ⟨_, same | ⟨boundary, rest', is_boundary, split'⟩⟩
  · exact absurd wild plain
  · have := congrArg List.length (same.symm.trans split)
    simp at this
  · rw [split] at split'
    have same := List.append_cancel_left split'
    simp only [List.cons.injEq] at same
    rw [same.1]
    exact is_boundary

theorem select_and_endpoints_always_return : SelectAndEndpointsAlwaysReturn := by
  refine ⟨fun blocks ref => WP.spec_mono (select_chooses_the_block blocks ref) fun _ _ => trivial,
    ?_⟩
  intro blocks host path ask fits
  obtain ⟨found, chosen⟩ := a_choice_exists blocks host path fits
  exact WP.spec_mono (endpoints_answers blocks host path ask fits found chosen) fun _ _ => trivial

end EndpointCore
