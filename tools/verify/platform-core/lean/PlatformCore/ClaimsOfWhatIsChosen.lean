-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `choose` answers, from what `best_of` answers for the whole index, and
-- the proofs of the claims of Spec.lean about it: that it returns, that what it names is an
-- acceptable image, the best and the first of the best, and that it names nothing exactly when
-- nothing matches.
-- Why it is needed: Theorems.lean ties each claim to its proof.
-- Read before this file: Spec.lean, TheBestOfAPart.lean.
-- Notation: `f x ⦃ r => P r ⦄` reads: the Rust function `f`, given `x`, returns and its answer `r`
-- satisfies `P r`.
import PlatformCore.ClaimsOfTheTable

open Aeneas Aeneas.Std Result velarx_platform_core

namespace PlatformCore

/-- **What `choose` answers**, in the words of `ImageMatches`: if it names the entry at `i`, that
entry matches some place `k` of the table, no image entry matches an earlier place, and every image
entry matching `k` is `i` or after it; and it names nothing exactly when no image entry matches. -/
theorem choose_answers (entries : Slice Entry) (want : Platform) :
    choose entries want ⦃ r =>
      (∀ i : Std.Usize, r = some i → ∃ k : Nat, ImageMatches entries want i.val k ∧
        ∀ j l : Nat, ImageMatches entries want j l → k ≤ l ∧ (l = k → i.val ≤ j)) ∧
      (r = none ↔ ∀ j l : Nat, ¬ ImageMatches entries want j l) ⦄ := by
  unfold choose
  step with best_of_answers entries want (Slice.len entries).val 0#usize (Slice.len entries)
    (by simp) (by simp) (by simp) as ⟨ best, answers ⟩
  obtain ⟨at_most_five, found, nothing⟩ := answers
  rw [most_is_five]
  by_cases below : best.rank < 5#usize
  · -- something matches: the entry named is the best
    simp only [below, ↓reduceIte]
    have below' : best.rank.val < 5 := by scalar_tac
    obtain ⟨from_start, in_index, matches_best, least⟩ := found below'
    refine (WP.spec_ok _).mpr ⟨fun i is_i => ?_, ?_⟩
    · injection is_i with is_i
      subst is_i
      exact ⟨best.rank.val, matches_best, fun j l matches_l =>
        least j l (Nat.zero_le j) (by
          obtain ⟨entry, at_j, _⟩ := matches_l
          exact (List.getElem?_eq_some_iff.mp at_j).1 |> fun h => by simpa [Slice.len_val] using h)
          matches_l⟩
    · exact ⟨fun is_none => by simp at is_none, fun none_match =>
        absurd matches_best (none_match _ _)⟩
  · -- nothing matches
    simp only [below, ↓reduceIte]
    have five : best.rank.val = 5 := by scalar_tac
    refine (WP.spec_ok _).mpr ⟨fun i is_i => by simp at is_i, ?_⟩
    · constructor
      · intro _ j l matches_l
        obtain ⟨entry, at_j, _⟩ := id matches_l
        have inside := (List.getElem?_eq_some_iff.mp at_j).1
        exact nothing five j l (Nat.zero_le j) (by simpa [Slice.len_val] using inside) matches_l
      · intro _; rfl

/-- Each function returns: its answer is what a claim about it says, so it is an answer. -/
theorem the_functions_always_return : TheFunctionsAlwaysReturn :=
  ⟨fun entries want => WP.spec_mono (choose_answers entries want) (fun _ _ => trivial),
   fun entry want => WP.spec_mono (rank_answers entry want) (fun _ _ => trivial),
   fun arch variant k room =>
     WP.spec_mono (wanted_variant_is_the_table arch variant k room) (fun _ _ => trivial)⟩

/-- The entry named matches a place of the table: so it is an image of the right operating system
and architecture, and its variant is in the table. -/
theorem the_chosen_entry_is_an_acceptable_image : TheChosenEntryIsAnAcceptableImage := by
  intro entries want
  refine WP.spec_mono (choose_answers entries want) ?_
  intro r ⟨named, _⟩ i is_i
  obtain ⟨k, ⟨entry, at_i, image, same_os, same_arch, at_k⟩, _⟩ := named i is_i
  exact ⟨entry, at_i, image, same_os, same_arch, List.mem_of_getElem? at_k⟩

/-- The entry named matches the place `kc` of the table and is the best and the first; if it also
matches the place `k`, then `k` is `kc` (an entry matches one place), so the claim says it. -/
theorem the_chosen_entry_is_the_best_and_the_first : TheChosenEntryIsTheBestAndTheFirst := by
  intro entries want
  refine WP.spec_mono (choose_answers entries want) ?_
  intro r ⟨named, _⟩ i k is_i matches_k j l matches_l
  obtain ⟨kc, matches_kc, best⟩ := named i is_i
  have same_place := an_entry_matches_one_place entries want _ _ _ matches_kc matches_k
  subst same_place
  exact best j l matches_l

/-- Nothing is named exactly when no image entry matches: the second half of `choose_answers`. -/
theorem nothing_is_chosen_exactly_when_nothing_matches :
    NothingIsChosenExactlyWhenNothingMatches := by
  intro entries want
  exact WP.spec_mono (choose_answers entries want) (fun _ ⟨_, nothing⟩ => nothing)

end PlatformCore
