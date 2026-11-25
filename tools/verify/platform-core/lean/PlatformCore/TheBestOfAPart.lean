-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `best_of` answers for a part `from..to` of an index, and so what
-- `choose` answers: the best entry of the part is the one whose place in the table of acceptable
-- platforms is the lowest, and of equal ones the first; its place in the table is 5 (`MOST`) when
-- no image entry of the part matches.
-- Why it is needed: `choose` is `best_of` over the whole index, and the claims about what is chosen
-- are read off this.
-- Read before this file: Spec.lean, TheRankOfAnEntry.lean.
-- Notation: `f x ⦃ r => P r ⦄` reads: the Rust function `f`, given `x`, returns and its answer `r`
-- satisfies `P r`.  `b.rank` and `b.at` are the two fields of an answer `b`: the place in the table
-- and the place in the index.  The function halves the part and calls itself on each half, so the
-- proof is an induction on the length of the part.
import PlatformCore.TheRankOfAnEntry

open Aeneas Aeneas.Std Result velarx_platform_core

namespace PlatformCore

/-- An entry of the index matches one place of the table at most. -/
theorem an_entry_matches_one_place (entries : Slice Entry) (want : Platform) (j k l : Nat)
    (at_k : ImageMatches entries want j k) (at_l : ImageMatches entries want j l) : k = l := by
  obtain ⟨entry, at_j, _, _, _, table_k⟩ := at_k
  obtain ⟨entry', at_j', _, _, _, table_l⟩ := at_l
  rw [at_j] at at_j'
  cases at_j'
  exact a_variant_has_one_place _ _ _ _ _ table_k table_l

/-- `b` is the best of the entries `start..stop` of the index (its places, `stop` not included): if
the place in the table it holds is below 5, it is the place of an image entry of the part that
matches that place, no image entry of the part matches an earlier place, and every one matching
that place is the entry named or after it; if it is 5, no image entry of the part matches at
all. -/
def BestOfPart (entries : Slice Entry) (want : Platform) (start stop : Nat) (b : Best) : Prop :=
  b.rank.val ≤ 5 ∧
  (b.rank.val < 5 → start ≤ b.at.val ∧ b.at.val < stop ∧
    ImageMatches entries want b.at.val b.rank.val ∧
    ∀ j l : Nat, start ≤ j → j < stop → ImageMatches entries want j l →
      b.rank.val ≤ l ∧ (l = b.rank.val → b.at.val ≤ j)) ∧
  (b.rank.val = 5 → ∀ j l : Nat, start ≤ j → j < stop → ¬ ImageMatches entries want j l)

/-- **Two parts side by side**: the best of the first part and the best of the second part are
the best of both, taking the second only when it is better (a lower place in the table): so of
equal places the first stays, which is the first in the index. -/
theorem the_better_of_two_parts (entries : Slice Entry) (want : Platform) (start middle stop : Nat)
    (first second : Best) (ordered : start ≤ middle ∧ middle ≤ stop)
    (in_first : BestOfPart entries want start middle first)
    (in_second : BestOfPart entries want middle stop second) :
    BestOfPart entries want start stop (if second.rank < first.rank then second else first) := by
  obtain ⟨first_le, first_best, first_none⟩ := in_first
  obtain ⟨second_le, second_best, second_none⟩ := in_second
  by_cases better : second.rank.val < first.rank.val
  · -- the second part has the better entry
    have better' : second.rank < first.rank := by scalar_tac
    simp only [better', ↓reduceIte]
    obtain ⟨from_middle, in_part, matches_best, least⟩ := second_best (by omega)
    refine ⟨second_le, fun _ => ⟨by omega, in_part, matches_best,
      fun j l from_j j_stop matches_l => ?_⟩, fun is_five => by omega⟩
    by_cases in_second_part : middle ≤ j
    · exact least j l in_second_part j_stop matches_l
    · -- an entry of the first part that matches is not better than the one of the first part
      have first_below : first.rank.val < 5 := by
        by_contra not_below
        exact first_none (by omega) j l from_j (by omega) matches_l
      obtain ⟨_, _, _, first_least⟩ := first_best first_below
      have := (first_least j l from_j (by omega) matches_l).1
      omega
  · -- the first part has the entry that is at least as good
    have better' : ¬ second.rank < first.rank := by scalar_tac
    simp only [better', ↓reduceIte]
    by_cases first_below : first.rank.val < 5
    · obtain ⟨from_start, in_part, matches_best, least⟩ := first_best first_below
      refine ⟨first_le, fun _ => ⟨from_start, by omega, matches_best,
        fun j l from_j j_stop matches_l => ?_⟩, fun is_five => by omega⟩
      by_cases in_first_part : j < middle
      · exact least j l from_j in_first_part matches_l
      · -- an entry of the second part that matches is not better than the first part's
        have second_below : second.rank.val < 5 := by
          by_contra not_below
          exact second_none (by omega) j l (by omega) j_stop matches_l
        obtain ⟨_, _, _, second_least⟩ := second_best second_below
        have at_least := (second_least j l (by omega) j_stop matches_l).1
        refine ⟨by omega, fun same => ?_⟩
        omega
    · refine ⟨first_le, fun below => absurd below first_below,
        fun is_five j l from_j j_stop matches_l => ?_⟩
      by_cases in_first_part : j < middle
      · exact first_none (by omega) j l from_j in_first_part matches_l
      · exact second_none (by omega) j l (by omega) j_stop matches_l

/-- **What `best_of` answers for the part `start..stop`** (of the places of the index, `start ≤ stop
≤` the length): the best entry of the part (`BestOfPart`).  It always returns. -/
theorem best_of_answers (entries : Slice Entry) (want : Platform) :
    ∀ (length : Nat) (start stop : Std.Usize), stop.val - start.val = length →
      start.val ≤ stop.val → stop.val ≤ entries.length →
      best_of entries want start stop ⦃ b => BestOfPart entries want start.val stop.val b ⦄ := by
  intro length
  induction length using Nat.strong_induction_on with
  | _ length smaller =>
    intro start stop is_length ordered in_index
    unfold best_of
    step as ⟨ size, is_size ⟩
    by_cases empty : size = 0#usize
    · -- no entry: nothing is found
      simp only [empty, ↓reduceIte]
      refine (WP.spec_ok _).mpr
        ⟨by rw [most_is_five]; simp, fun below => ?_, fun _ j l from_j j_stop => ?_⟩
      · rw [most_is_five] at below; simp at below
      · scalar_tac
    by_cases one : size = 1#usize
    · -- one entry: its own place
      have one_is_not_zero : ¬ (1#usize = 0#usize) := by decide
      simp only [one, one_is_not_zero, ↓reduceIte]
      have inside : start.val < entries.length := by scalar_tac
      step with rank_at_answers entries start want inside as ⟨ k, at_most_five, matches_k, five ⟩
      refine ⟨at_most_five, fun below => ?_, fun is_five j l from_j j_stop => ?_⟩
      · refine ⟨le_refl _, by scalar_tac, matches_k below, fun j l from_j j_stop matches_l => ?_⟩
        have same_place : j = start.val := by scalar_tac
        rw [same_place] at matches_l
        have := an_entry_matches_one_place entries want _ _ _ (matches_k below) matches_l
        show k.val ≤ l ∧ (l = k.val → start.val ≤ j)
        omega
      · have same_place : j = start.val := by scalar_tac
        rw [same_place]
        exact five is_five l
    · -- two entries or more: the two halves
      have not_one : ¬ (size = 1#usize) := one
      simp only [empty, one, ↓reduceIte]
      step as ⟨ half, is_half ⟩
      step as ⟨ middle, is_middle ⟩
      have two_or_more : 2 ≤ stop.val - start.val := by scalar_tac
      step with smaller (middle.val - start.val) (by omega) start middle rfl (by omega) (by omega)
        as ⟨ first, in_first ⟩
      step with smaller (stop.val - middle.val) (by omega) middle stop rfl (by omega) in_index
        as ⟨ second, in_second ⟩
      have combined := the_better_of_two_parts entries want start.val middle.val stop.val first
        second ⟨by omega, by omega⟩ in_first in_second
      by_cases better : second.rank < first.rank
      · simp only [better, ↓reduceIte] at combined ⊢
        exact (WP.spec_ok _).mpr combined
      · simp only [better, ↓reduceIte] at combined ⊢
        exact (WP.spec_ok _).mpr combined

end PlatformCore
