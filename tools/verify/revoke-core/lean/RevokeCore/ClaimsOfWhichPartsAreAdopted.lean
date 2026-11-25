-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the claims of Spec.lean about the return of `newer` and
-- `adopt` and about which parts are adopted: `newer_and_adopt_always_return`,
-- `newer_means_higher_than_every_number_held`,
-- `adopts_exactly_the_unbeaten_newer_verified_parts`, `one_part_of_an_issuer_at_most`,
-- `a_higher_verified_part_is_always_adopted`, `unverified_parts_are_never_adopted` and
-- `unverified_parts_are_not_there`.
-- Why it is needed: Theorems.lean ties each claim of Spec.lean to a proof, and these are the
-- proofs, each a short step from what AdoptLoop.lean and NewerLoop.lean show.
-- Read before this file: Spec.lean, AdoptLoop.lean.
-- Notation: `WP.spec_mono h ?_` is "use the result `h` about the function, and show that what it
-- says is enough".
import RevokeCore.AdoptLoop
import RevokeCore.ReturnedAnswers

open Aeneas Aeneas.Std Result velarx_revoke_core

open Classical

namespace RevokeCore

/-- **`adopt` answers exactly the places that are adopted**, in the two forms the claims use: a
place is in the answer exactly when its part is adopted, and the places increase. -/
theorem the_places_are_the_adopted (held : Slice Held) (parts : Slice Part) :
    adopt held parts ⦃ adopted =>
      (∀ i, i ∈ Places adopted ↔ AdoptedAt held.val parts.val i) ∧
      (Places adopted).Pairwise (· < ·) ⦄ := by
  refine WP.spec_mono (adopt_answers_the_places held parts) ?_
  intro adopted places
  rw [places]
  refine ⟨?_, ?_⟩
  · intro i
    simp only [AdoptedFrom, List.drop_zero, List.mem_filter, List.mem_range, decide_eq_true_eq]
    constructor
    · exact fun ⟨_, adopted⟩ => adopted
    · intro adopted_here
      have ⟨p, at_i, _⟩ := adopted_here
      exact ⟨(List.getElem?_eq_some_iff.mp at_i).1, adopted_here⟩
  · simp only [AdoptedFrom, List.drop_zero]
    exact List.Pairwise.filter _ List.pairwise_lt_range

theorem newer_and_adopt_always_return : NewerAndAdoptAlwaysReturn :=
  ⟨fun held issuer number =>
    WP.spec_mono (newer_is_newer_than_held held issuer number) fun _ _ => trivial,
   fun held parts => WP.spec_mono (the_places_are_the_adopted held parts) fun _ _ => trivial⟩

theorem newer_means_higher_than_every_number_held : NewerMeansHigherThanEveryNumberHeld :=
  newer_is_newer_than_held

theorem adopts_exactly_the_unbeaten_newer_verified_parts :
    AdoptsExactlyTheUnbeatenNewerVerifiedParts :=
  the_places_are_the_adopted

/-- What `adopt` answers, when it answers `adopted`: the two forms of the previous theorem. -/
theorem places_when_adopt_answers (held : Slice Held) (parts : Slice Part)
    (adopted : alloc.vec.Vec Std.Usize) (answers : adopt held parts = ok adopted) :
    ∀ i, i ∈ Places adopted ↔ AdoptedAt held.val parts.val i :=
  (answer_has (the_places_are_the_adopted held parts) answers).1

theorem one_part_of_an_issuer_at_most : OnePartOfAnIssuerAtMost := by
  intro held parts adopted answers i j p q i_adopted j_adopted at_i at_j same_issuer
  have places := places_when_adopt_answers held parts adopted answers
  obtain ⟨p', at_i', adopts_i⟩ := (places i).mp i_adopted
  obtain ⟨q', at_j', adopts_j⟩ := (places j).mp j_adopted
  rw [at_i] at at_i'
  rw [at_j] at at_j'
  cases at_i'
  cases at_j'
  obtain ⟨verified_i, _, _⟩ := (adopts_is_not_beaten held.val parts.val i p at_i).mp adopts_i
  obtain ⟨verified_j, _, _⟩ := (adopts_is_not_beaten held.val parts.val j q at_j).mp adopts_j
  have not_beaten_i := ((adopts_is_not_beaten held.val parts.val i p at_i).mp adopts_i).2.2
  have not_beaten_j := ((adopts_is_not_beaten held.val parts.val j q at_j).mp adopts_j).2.2
  by_contra different
  rcases Nat.lt_or_gt_of_ne different with earlier | later
  · -- the part at `i` is first: either it is higher, or it is equal and first: it beats `j`
    by_cases higher : q.number.val < p.number.val
    · exact not_beaten_j i (Nat.zero_le i)
        ⟨p, q, at_i, at_j, verified_i, same_issuer, Or.inl higher⟩
    · by_cases equal : q.number.val = p.number.val
      · exact not_beaten_j i (Nat.zero_le i)
          ⟨p, q, at_i, at_j, verified_i, same_issuer, Or.inr ⟨equal.symm, earlier⟩⟩
      · exact not_beaten_i j (Nat.zero_le j)
          ⟨q, p, at_j, at_i, verified_j, same_issuer.symm, Or.inl (by omega)⟩
  · by_cases higher : p.number.val < q.number.val
    · exact not_beaten_i j (Nat.zero_le j)
        ⟨q, p, at_j, at_i, verified_j, same_issuer.symm, Or.inl higher⟩
    · by_cases equal : p.number.val = q.number.val
      · exact not_beaten_i j (Nat.zero_le j)
          ⟨q, p, at_j, at_i, verified_j, same_issuer.symm, Or.inr ⟨equal.symm, later⟩⟩
      · exact not_beaten_j i (Nat.zero_le i)
          ⟨p, q, at_i, at_j, verified_i, same_issuer, Or.inl (by omega)⟩

theorem a_higher_verified_part_is_always_adopted : AHigherVerifiedPartIsAlwaysAdopted := by
  intro held parts adopted answers i p at_i verified newer lower
  refine (places_when_adopt_answers held parts adopted answers i).mpr ⟨p, at_i, ?_⟩
  refine (adopts_is_not_beaten held.val parts.val i p at_i).mpr ⟨verified, newer, ?_⟩
  rintro k _ ⟨q, p', at_k, at_i', q_verified, same_issuer, order⟩
  rw [at_i] at at_i'
  cases at_i'
  by_cases same_place : k = i
  · subst same_place
    rw [at_i] at at_k
    cases at_k
    omega
  · have := lower k q same_place at_k q_verified same_issuer
    omega

theorem unverified_parts_are_never_adopted : UnverifiedPartsAreNeverAdopted := by
  intro held parts adopted answers i p at_i unverified i_adopted
  obtain ⟨p', at_i', adopts⟩ :=
    (places_when_adopt_answers held parts adopted answers i).mp i_adopted
  rw [at_i] at at_i'
  cases at_i'
  have verified := adopts.1
  simp [unverified] at verified

/-- The parts that are not verified take no part in `Adopts`: asking it of the parts before and
after, or of those of them that are verified, is the same. -/
theorem adopts_looks_only_at_the_verified (held : List Held) (before after : List Part) (p : Part) :
    Adopts held before p after ↔
      Adopts held (before.filter fun q => q.verified = true) p
        (after.filter fun q => q.verified = true) := by
  simp only [Adopts, List.mem_filter, decide_eq_true_eq]
  constructor
  · rintro ⟨verified, newer, before_lower, after_not_higher⟩
    exact ⟨verified, newer, fun q ⟨member, v⟩ _ same => before_lower q member v same,
      fun q ⟨member, v⟩ _ same => after_not_higher q member v same⟩
  · rintro ⟨verified, newer, before_lower, after_not_higher⟩
    exact ⟨verified, newer, fun q member v same => before_lower q ⟨member, v⟩ v same,
      fun q member v same => after_not_higher q ⟨member, v⟩ v same⟩

theorem unverified_parts_are_not_there : UnverifiedPartsAreNotThere := by
  intro held parts kept adopted kept_adopted is_kept answers kept_answers before p after
    split verified
  have in_parts := places_when_adopt_answers held parts adopted answers
  have in_kept := places_when_adopt_answers held kept kept_adopted kept_answers
  have kept_split : kept.val = (before.filter fun q => q.verified = true) ++ p ::
      (after.filter fun q => q.verified = true) := by
    rw [is_kept, split, List.filter_append, List.filter_cons_of_pos (by simpa using verified)]
  rw [in_parts, in_kept]
  have take_before : (before ++ p :: after).take before.length = before := by simp
  have drop_before : (before ++ p :: after).drop (before.length + 1) = after := by simp
  have at_before : (before ++ p :: after)[before.length]? = some p := by simp
  have take_kept : (kept.val).take (before.filter fun q => q.verified = true).length =
      before.filter fun q => q.verified = true := by rw [kept_split]; simp
  have drop_kept : (kept.val).drop ((before.filter fun q => q.verified = true).length + 1) =
      after.filter fun q => q.verified = true := by rw [kept_split]; simp
  have at_kept : kept.val[(before.filter fun q => q.verified = true).length]? = some p := by
    rw [kept_split]; simp
  rw [split]
  constructor
  · rintro ⟨p', at_p', adopts⟩
    rw [at_before] at at_p'
    cases at_p'
    rw [take_before, drop_before] at adopts
    refine ⟨p, at_kept, ?_⟩
    rw [take_kept, drop_kept]
    exact (adopts_looks_only_at_the_verified _ _ _ _).mp adopts
  · rintro ⟨p', at_p', adopts⟩
    rw [at_kept] at at_p'
    cases at_p'
    rw [take_kept, drop_kept] at adopts
    refine ⟨p, at_before, ?_⟩
    rw [take_before, drop_before]
    exact (adopts_looks_only_at_the_verified _ _ _ _).mpr adopts

end RevokeCore
