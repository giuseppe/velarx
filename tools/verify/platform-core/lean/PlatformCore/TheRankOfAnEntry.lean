-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `rank` answers: the place of an entry's platform in the table of the
-- acceptable platforms of the request (`Accepts` of Spec.lean), none if it is not there; and what
-- `rank_at` answers for the entry at a place of an index: its place if it is an image, `MOST` (5)
-- if it is not acceptable or not an image.
-- Why it is needed: `choose` compares these places, and the claims about what is chosen are about
-- the entries that `ImageMatches`.
-- Read before this file: Spec.lean, TheAcceptableVariants.lean.
-- Notation: `loop body x ⦃ post ⦄` reads: the loop returns and its answer satisfies `post`.
-- `step` goes through one line of the Rust function; `scalar_tac` proves a fact about the numbers
-- of the machine (`usize`) by arithmetic.
import PlatformCore.TheAcceptableVariants

open Aeneas Aeneas.Std Result velarx_platform_core

namespace PlatformCore

/-- `MOST` is 5, the most platforms a request has. -/
theorem most_is_five : MOST = 5#usize := by
  unfold MOST; rfl

/-- A request has at most five acceptable platforms (none and four variants). -/
theorem at_most_five_are_acceptable (arch variant : List Std.U8) :
    (Acceptable arch variant).length ≤ 5 := by
  have few := at_most_four_are_known arch
  unfold Acceptable
  by_cases none_asked : variant = []
  · simp only [none_asked, ↓reduceIte, List.length_cons]; omega
  · simp only [none_asked, ↓reduceIte]
    by_cases known : variant ∈ Known arch
    · simp only [known, ↓reduceIte, List.length_append, List.length_drop, List.length_singleton]
      omega
    · simp only [known, ↓reduceIte]; simp

/-- **The loop of `rank`** walks down the acceptable variants of the request (`want_arch`,
`want_variant`) from the place `k`, and stops at the first that is the variant `entry_variant`.
Started with nothing found, from the place 0, it answers a place where the table has the variant,
or nothing when the table does not have it at all; it always returns. -/
theorem rank_loop_answers (entry_variant want_arch want_variant : Slice Std.U8) :
    rank_loop entry_variant want_arch want_variant none 0#usize true ⦃ r =>
      (∀ j : Std.Usize, r = some j →
        (Acceptable want_arch.val want_variant.val)[j.val]? = some entry_variant.val) ∧
      (r = none → ∀ j : Nat,
        (Acceptable want_arch.val want_variant.val)[j]? ≠ some entry_variant.val) ⦄ := by
  unfold rank_loop
  have five := at_most_five_are_acceptable want_arch.val want_variant.val
  apply loop.spec_decr_nat (fun (q : Option Std.Usize × Std.Usize × Bool) => 5 - q.2.1.val)
    (fun (q : Option Std.Usize × Std.Usize × Bool) =>
      q.2.1.val ≤ 5 ∧
      (∀ j : Std.Usize, q.1 = some j →
        (Acceptable want_arch.val want_variant.val)[j.val]? = some entry_variant.val) ∧
      (q.1 = none → ∀ j : Nat, j < q.2.1.val →
        (Acceptable want_arch.val want_variant.val)[j]? ≠ some entry_variant.val) ∧
      (q.2.2 = true → q.1 = none) ∧
      (q.2.2 = false → q.1 ≠ none ∨ ∀ j : Nat,
        (Acceptable want_arch.val want_variant.val)[j]? ≠ some entry_variant.val))
  · rintro ⟨found, k, going⟩ ⟨k_le, found_is, none_before, going_none, stopped⟩
    simp only at k_le found_is none_before going_none stopped ⊢
    unfold rank_loop.body
    rw [most_is_five]
    by_cases inside : k < 5#usize
    · simp only [inside, ↓reduceIte]
      by_cases still : going = true
      · -- the walk goes on: the acceptable variant at `k` is looked at
        simp only [still, ↓reduceIte]
        have found_none := going_none still
        have room : k.val + 4 ≤ Std.Usize.max := by scalar_tac
        step with wanted_variant_answers_the_table want_arch want_variant k room as ⟨ o, is_o ⟩
        subst found_none
        cases o with
        | none =>
          -- the table ends here: nothing is found, and nothing is left to find
          simp only
          step as ⟨ k2, is_k2 ⟩
          have table_ends : (Acceptable want_arch.val want_variant.val).length ≤ k.val := by
            have := is_o
            simp only [Option.map_none] at this
            exact List.getElem?_eq_none_iff.mp this.symm
          refine ⟨by scalar_tac, found_is, fun _ j below => ?_, by simp, fun _ => Or.inr ?_,
            by scalar_tac⟩
          · by_cases earlier : j < k.val
            · exact none_before rfl j earlier
            · rw [List.getElem?_eq_none (by omega)]; simp
          · intro j
            by_cases earlier : j < k.val
            · exact none_before rfl j earlier
            · rw [List.getElem?_eq_none (by omega)]; simp
        | some w =>
          -- the table has the variant `w` at this place: is it the entry's?
          step as ⟨ same, is_same ⟩
          have at_k : (Acceptable want_arch.val want_variant.val)[k.val]? =
              some (WantedBytes want_variant.val w) := by
            rw [← is_o]; rfl
          by_cases found : same = true
          · -- it is: this place is the answer, and the walk stops
            simp only [found, ↓reduceIte]
            step as ⟨ k2, is_k2 ⟩
            refine ⟨by scalar_tac, fun j is_j => ?_, fun is_none => ?_, fun still => ?_,
              fun _ => Or.inl (by simp), by scalar_tac⟩
            · simp only [Option.some.injEq] at is_j
              rw [← is_j, at_k, is_same.mp found]
            · simp at is_none
            · simp at still
          · -- it is not: the walk goes on to the next place
            simp only [found, Bool.false_eq_true, ↓reduceIte]
            step as ⟨ k2, is_k2 ⟩
            refine ⟨by scalar_tac, found_is, fun _ j below => ?_, fun _ => by simp, fun still => ?_,
              by scalar_tac⟩
            · by_cases earlier : j < k.val
              · exact none_before rfl j earlier
              · have : j = k.val := by scalar_tac
                rw [this, at_k]
                intro same_variant
                injection same_variant with same_variant
                exact found (is_same.mpr same_variant.symm)
            · simp at still
      · -- the walk has stopped: the loop ends with what was found
        simp only [still, Bool.false_eq_true, ↓reduceIte]
        refine (WP.spec_ok _).mpr ⟨found_is, fun is_none j => ?_⟩
        have := stopped (by simpa using still)
        rcases this with some_found | nothing
        · exact absurd is_none some_found
        · exact nothing j
    · -- no place is left: the table has no variant that was not looked at
      simp only [inside, ↓reduceIte]
      refine (WP.spec_ok _).mpr ⟨found_is, fun is_none j => ?_⟩
      have at_the_end : 5 ≤ k.val := by scalar_tac
      by_cases earlier : j < k.val
      · exact none_before is_none j earlier
      · rw [List.getElem?_eq_none (by omega)]; simp
  · exact ⟨by simp, fun j is_j => by simp at is_j, fun _ j below => by simp at below,
      fun _ => rfl, fun is_false => by simp at is_false⟩

/-- A variant is at one place of the table of acceptable variants at most. -/
theorem a_variant_has_one_place (arch variant : List Std.U8) (j k : Nat) (v : List Std.U8)
    (at_j : (Acceptable arch variant)[j]? = some v)
    (at_k : (Acceptable arch variant)[k]? = some v) :
    j = k := by
  obtain ⟨j_inside, is_j⟩ := List.getElem?_eq_some_iff.mp at_j
  obtain ⟨k_inside, is_k⟩ := List.getElem?_eq_some_iff.mp at_k
  exact (acceptable_has_no_repeats arch variant).getElem_inj_iff.mp (is_j.trans is_k.symm)

/-- **`rank` is the place in the table**: it answers `some k` exactly when the platform of the entry
has the operating system and the architecture asked for and the `k`-th acceptable variant, and none
exactly when no place of the table does. -/
theorem rank_answers (entry want : Platform) : rank entry want ⦃ r =>
    (∀ k : Std.Usize, r = some k ↔ Accepts want entry k.val) ∧
    (r = none ↔ ∀ k : Nat, ¬ Accepts want entry k) ⦄ := by
  unfold rank
  step as ⟨ same_os, is_same_os ⟩
  by_cases os : same_os = true
  · simp only [os, ↓reduceIte]
    step as ⟨ same_arch, is_same_arch ⟩
    by_cases arch : same_arch = true
    · -- the operating system and the architecture are the ones asked for
      simp only [arch, ↓reduceIte]
      refine WP.spec_mono (rank_loop_answers entry.variant want.arch want.variant) ?_
      intro r ⟨found_is, none_is⟩
      refine ⟨fun k => ⟨fun is_k => ⟨is_same_os.mp os, is_same_arch.mp arch, found_is k is_k⟩,
        fun ⟨_, _, at_k⟩ => ?_⟩,
        ⟨fun is_none k ⟨_, _, at_k⟩ => none_is is_none k at_k, fun no_place => ?_⟩⟩
      · cases r with
        | none => exact absurd at_k (none_is rfl k.val)
        | some j =>
          have := a_variant_has_one_place _ _ _ _ _ (found_is j rfl) at_k
          rw [Std.UScalar.eq_of_val_eq this]
      · cases r with
        | none => rfl
        | some j =>
          exact absurd ⟨is_same_os.mp os, is_same_arch.mp arch, found_is j rfl⟩ (no_place j.val)
    · simp only [arch, Bool.false_eq_true, ↓reduceIte]
      refine (WP.spec_ok _).mpr ⟨fun k => ⟨fun is_k => by simp at is_k, fun ⟨_, same, _⟩ => ?_⟩,
        ⟨fun _ k ⟨_, same, _⟩ => ?_, fun _ => rfl⟩⟩
      · exact absurd (is_same_arch.mpr same) arch
      · exact arch (is_same_arch.mpr same)
  · simp only [os, Bool.false_eq_true, ↓reduceIte]
    refine (WP.spec_ok _).mpr ⟨fun k => ⟨fun is_k => by simp at is_k, fun ⟨same, _⟩ => ?_⟩,
      ⟨fun _ k ⟨same, _⟩ => ?_, fun _ => rfl⟩⟩
    · exact absurd (is_same_os.mpr same) os
    · exact os (is_same_os.mpr same)

/-- **`rank_at` is the place of the entry at `i`** in the table of `want` when it is an image that
matches, and 5 (`MOST`) when no platform of the table is the entry's or the entry is not an image;
`i` is a place of the index. -/
theorem rank_at_answers (entries : Slice Entry) (i : Std.Usize) (want : Platform)
    (inside : i.val < entries.length) :
    rank_at entries i want ⦃ k =>
      k.val ≤ 5 ∧ (k.val < 5 → ImageMatches entries want i.val k.val) ∧
      (k.val = 5 → ∀ l : Nat, ¬ ImageMatches entries want i.val l) ⦄ := by
  unfold rank_at
  step as ⟨ entry, is_entry ⟩
  have at_i : entries.val[i.val]? = some entry := by
    rw [is_entry]; exact List.getElem?_eq_getElem inside
  by_cases image : entry.image = true
  · -- an image: its place in the table
    simp only [image, ↓reduceIte]
    step with rank_answers entry.platform want as ⟨ o, some_place, none_place ⟩
    cases o with
    | none =>
      refine (WP.spec_ok _).mpr ⟨by rw [most_is_five]; simp, fun below => ?_,
        fun _ l ⟨entry', at_i', _, accepts⟩ => ?_⟩
      · rw [most_is_five] at below; simp at below
      · rw [at_i] at at_i'
        cases at_i'
        exact none_place.mp rfl l accepts
    | some k =>
      have accepts := (some_place k).mp rfl
      have inside_table := (List.getElem?_eq_some_iff.mp accepts.2.2).1
      have := at_most_five_are_acceptable want.arch.val want.variant.val
      refine (WP.spec_ok _).mpr ⟨by omega, fun _ => ⟨entry, at_i, image, accepts⟩, fun five => ?_⟩
      omega
  · -- not an image: never chosen
    simp only [image, Bool.false_eq_true, ↓reduceIte]
    refine (WP.spec_ok _).mpr ⟨by rw [most_is_five]; simp, fun below => ?_,
      fun _ l ⟨entry', at_i', is_image, _⟩ => ?_⟩
    · rw [most_is_five] at below; simp at below
    · rw [at_i] at at_i'
      cases at_i'
      exact image is_image

end PlatformCore
