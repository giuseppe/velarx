-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the claims of Spec.lean about what is held after the
-- adoption:
-- `the_number_held_after_is_the_greatest`, `the_number_held_never_decreases`,
-- `the_order_of_the_parts_does_not_matter` and `adopting_again_adopts_nothing`.
-- Why it is needed: Theorems.lean ties each claim of Spec.lean to a proof, and these are the
-- proofs.  The first is the one the others are read from: of each issuer the number held after is
-- the highest of the numbers held before and the numbers of the verified parts.
-- Read before this file: Spec.lean, ClaimsOfWhichPartsAreAdopted.lean, NumbersAfter.lean,
-- TheHighestVerifiedPart.lean, SameHighestNumber.lean.
-- Notation: `l.max?` is the highest number of the list `l`; `l.Perm l'` is "`l'` has the elements
-- of `l` in another order".
import RevokeCore.ClaimsOfWhichPartsAreAdopted
import RevokeCore.NumbersAfter
import RevokeCore.TheHighestVerifiedPart
import RevokeCore.SameHighestNumber

open Aeneas Aeneas.Std Result velarx_revoke_core

open Classical

namespace RevokeCore

/-- **The number held after is the highest of those held before and those of the verified
parts.**  `adopted` is what `adopt` answers for `held` and `parts`. -/
theorem highest_held_after (held : Slice Held) (parts : Slice Part)
    (adopted : alloc.vec.Vec Std.Usize) (answers : adopt held parts = ok adopted)
    (issuer : Std.U64) :
    (NumbersHeld (StateAfter held.val parts.val (Places adopted)) issuer).max? =
      (NumbersHeld held.val issuer ++ NumbersVerified parts.val issuer).max? := by
  have places := places_when_adopt_answers held parts adopted answers
  -- what an adopted part of the issuer is like
  have adopted_is_highest : ∀ i ∈ Places adopted, ∀ a, parts.val[i]? = some a →
      a.issuer = issuer → a.number.val ∈ NumbersVerified parts.val issuer ∧
        (∀ x ∈ NumbersVerified parts.val issuer, x ≤ a.number.val) ∧
        ∀ n ∈ NumbersHeld held.val issuer, n < a.number.val := by
    intro i in_places a at_i same
    have adopts := (places i).mp in_places
    have highest := an_adopted_part_is_the_highest held.val parts.val i a at_i adopts
    obtain ⟨_, at_i', adopts⟩ := adopts
    rw [at_i] at at_i'
    cases at_i'
    obtain ⟨_, newer, _⟩ := adopts
    rw [same] at highest
    exact ⟨highest.1, highest.2, by rw [← same]; exact newer⟩
  apply same_highest
  · -- every number held after is one held before or the number of a verified part
    intro x x_in
    rcases (number_held_after held.val parts.val (Places adopted) issuer x).mp x_in with
      ⟨held_before, _⟩ | ⟨i, in_places, a, at_i, same, is_x⟩
    · exact ⟨x, List.mem_append_left _ held_before, le_refl x⟩
    · have := (adopted_is_highest i in_places a at_i same).1
      rw [is_x] at this
      exact ⟨x, List.mem_append_right _ this, le_refl x⟩
  · -- every number held before or of a verified part is at most one held after
    intro y y_in
    by_cases some_adopted : ∃ i ∈ Places adopted, ∃ a, parts.val[i]? = some a ∧ a.issuer = issuer
    · -- a part of the issuer is adopted: it has the highest number, and is newer than the held
      obtain ⟨i, in_places, a, at_i, same⟩ := some_adopted
      obtain ⟨_, highest, newer⟩ := adopted_is_highest i in_places a at_i same
      refine ⟨a.number.val, (number_held_after _ _ _ _ _).mpr (Or.inr ⟨i, in_places, a, at_i, same,
        rfl⟩), ?_⟩
      rcases List.mem_append.mp y_in with held_before | verified
      · exact (newer y held_before).le
      · exact highest y verified
    · -- no part of the issuer is adopted: what is held stays
      have kept : ∀ i ∈ Places adopted, ∀ a, parts.val[i]? = some a → a.issuer ≠ issuer :=
        fun i in_places a at_i same => some_adopted ⟨i, in_places, a, at_i, same⟩
      have held_stays : ∀ n ∈ NumbersHeld held.val issuer,
          n ∈ NumbersHeld (StateAfter held.val parts.val (Places adopted)) issuer :=
        fun n member => (number_held_after _ _ _ _ _).mpr (Or.inl ⟨member, kept⟩)
      rcases List.mem_append.mp y_in with held_before | verified
      · exact ⟨y, held_stays y held_before, le_refl y⟩
      · -- a verified part has a number: the highest one is not newer than the numbers held
        obtain ⟨top, is_top, y_below⟩ := highest_exists _ y verified
        rcases the_highest_is_adopted_or_held held.val parts.val issuer top is_top with
          ⟨i, adopts, a, at_i, same, _⟩ | ⟨n, n_held, top_below⟩
        · exact absurd ⟨i, (places i).mpr adopts, a, at_i, same⟩ some_adopted
        · exact ⟨n, held_stays n n_held, by omega⟩

theorem the_number_held_after_is_the_greatest : TheNumberHeldAfterIsTheGreatest :=
  highest_held_after

theorem the_number_held_never_decreases : TheNumberHeldNeverDecreases := by
  intro held parts adopted answers issuer b is_b
  rw [highest_held_after held parts adopted answers issuer]
  have b_in := (List.max?_eq_some_iff.mp is_b).1
  obtain ⟨top, is_top, b_below⟩ := highest_exists _ b (List.mem_append_left _ b_in)
  exact ⟨top, is_top, b_below⟩

theorem the_order_of_the_parts_does_not_matter : TheOrderOfThePartsDoesNotMatter := by
  intro held parts parts' adopted adopted' reordered answers answers' issuer
  rw [highest_held_after held parts adopted answers issuer,
    highest_held_after held parts' adopted' answers' issuer]
  apply highest_of_a_reordering
  apply List.Perm.append_left
  simp only [NumbersVerified]
  exact (reordered.filter _).map _

theorem adopting_again_adopts_nothing : AdoptingAgainAdoptsNothing := by
  intro held parts adopted held' answers is_held'
  obtain ⟨again, answers_again, places_again, _⟩ :=
    returned_answer (the_places_are_the_adopted held' parts)
  refine ⟨again, answers_again, ?_⟩
  have nothing : Places again = [] := by
    apply List.eq_nil_iff_forall_not_mem.mpr
    intro i in_places
    obtain ⟨a, at_i, adopts⟩ := (places_again i).mp in_places
    obtain ⟨verified, newer, _⟩ := (adopts_is_not_beaten held'.val parts.val i a at_i).mp adopts
    -- what is held now has a number as high as the part has
    have a_in : a.number.val ∈
        NumbersHeld held.val a.issuer ++ NumbersVerified parts.val a.issuer :=
      List.mem_append_right _ ((an_adopted_part_is_the_highest held'.val parts.val i a at_i
        ((places_again i).mp in_places)).1)
    obtain ⟨top, is_top, a_below⟩ := highest_exists _ _ a_in
    have held_now := highest_held_after held parts adopted answers a.issuer
    rw [is_top] at held_now
    have top_held := (List.max?_eq_some_iff.mp held_now).1
    rw [is_held'] at newer
    have := newer top top_held
    omega
  simpa [Places] using nothing

end RevokeCore
