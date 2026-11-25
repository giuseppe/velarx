-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proof of `WorkedExamples` of Spec.lean: the table of `arm`, `arm64`
-- and `amd64`, and the entry that `choose` takes in each example (`arm` with `v7` takes v7, with
-- `v6` takes v6, `arm64` with and without a variant, an attestation skipped).
-- Why it is needed: Theorems.lean ties each claim to its proof.  The examples are not computed from
-- the code: each is worked out from the three claims about what is chosen
-- (`TheChosenEntryIsAnAcceptableImage`, `TheChosenEntryIsTheBestAndTheFirst`,
-- `NothingIsChosenExactlyWhenNothingMatches`), by reading what the entries of the example say,
-- so they show that the claims give the answer a reader expects.
-- Read before this file: Spec.lean, ClaimsOfWhatIsChosen.lean.
-- Notation: `decide` computes a statement about small fixed lists; `rcases j with _ | _ | j`
-- splits on the places 0, 1 and the rest.
import PlatformCore.ClaimsOfWhatIsChosen

open Aeneas Aeneas.Std Result velarx_platform_core

namespace PlatformCore

/-- **The entry that is best and first is the one chosen.**  If the entry at the place `i` of the
index is an image matching the place `k` of the table, and every image entry that matches some
place matches one that is not before `k`, and the ones that match `k` are not before `i`, then
`choose` names `i`.  (From the three claims about what is chosen.) -/
theorem the_best_and_first_entry_is_chosen (entries : Slice Entry) (want : Platform)
    (i : Std.Usize) (k : Nat) (matches_i : ImageMatches entries want i.val k)
    (best : ∀ j l : Nat, ImageMatches entries want j l → k ≤ l ∧ (l = k → i.val ≤ j)) :
    choose entries want ⦃ r => r = some i ⦄ := by
  have claims := WP.spec_and
    (WP.spec_and (the_chosen_entry_is_an_acceptable_image entries want)
      (the_chosen_entry_is_the_best_and_the_first entries want))
    (nothing_is_chosen_exactly_when_nothing_matches entries want)
  refine WP.spec_mono claims ?_
  rintro r ⟨⟨acceptable, first⟩, nothing⟩
  cases r with
  | none => exact absurd matches_i (nothing.mp rfl i.val k)
  | some chosen =>
    obtain ⟨entry, at_chosen, image, same_os, same_arch, variant_in⟩ := acceptable chosen rfl
    obtain ⟨k', at_k'⟩ := List.mem_iff_getElem?.mp variant_in
    have matches_chosen : ImageMatches entries want chosen.val k' :=
      ⟨entry, at_chosen, image, same_os, same_arch, at_k'⟩
    have not_after := first chosen k' rfl matches_chosen i.val k matches_i
    have chosen_best := best chosen.val k' matches_chosen
    have : chosen.val = i.val := by omega
    rw [Std.UScalar.eq_of_val_eq this]

/-- **Nothing is chosen when no entry is an image**: an index of attestations only. -/
theorem nothing_is_chosen_from_attestations (entries : Slice Entry) (want : Platform)
    (attestations : ∀ entry ∈ entries.val, entry.image = false) :
    choose entries want ⦃ r => r = none ⦄ := by
  refine WP.spec_mono (nothing_is_chosen_exactly_when_nothing_matches entries want) ?_
  intro r nothing
  apply nothing.mpr
  intro j l ⟨entry, at_j, image, _⟩
  rw [attestations entry (List.mem_of_getElem? at_j)] at image
  exact Bool.false_ne_true image

/-- The entry at a place of the index is the one described at that place. -/
theorem the_entry_is_the_one_described (entries : Slice Entry)
    (ds : List (String × String × String × Bool)) (described : Describes entries ds)
    (j : Nat) (entry : Entry) (at_j : entries.val[j]? = some entry) :
    ∃ d, ds[j]? = some d ∧ IsEntry entry d := by
  unfold Describes at described
  generalize entries.val = es at described at_j
  induction described generalizing j with
  | nil => simp at at_j
  | cons same _ ih =>
    cases j with
    | zero =>
      simp only [List.getElem?_cons_zero, Option.some.injEq] at at_j
      subst at_j
      exact ⟨_, rfl, same⟩
    | succ j => exact ih j at_j

/-- The place of the index that is described has an entry that is the one described. -/
theorem the_entry_described_is_there (entries : Slice Entry)
    (ds : List (String × String × String × Bool)) (described : Describes entries ds)
    (j : Nat) (d : String × String × String × Bool) (at_j : ds[j]? = some d) :
    ∃ entry, entries.val[j]? = some entry ∧ IsEntry entry d := by
  unfold Describes at described
  generalize entries.val = es at described ⊢
  induction described generalizing j with
  | nil => simp at at_j
  | cons same _ ih =>
    cases j with
    | zero =>
      simp only [List.getElem?_cons_zero, Option.some.injEq] at at_j
      subst at_j
      exact ⟨_, rfl, same⟩
    | succ j => exact ih j at_j

/-- `arm` with `v7` against the entries v5, v6, v7, v8 takes v7, the third. -/
theorem arm_v7_takes_v7 (entries : Slice Entry) (want : Platform)
    (described : Describes entries [("linux", "arm", "v5", true), ("linux", "arm", "v6", true),
      ("linux", "arm", "v7", true), ("linux", "arm", "v8", true)])
    (asks : Asks want "linux" "arm" "v7") : choose entries want ⦃ r => r = some 2#usize ⦄ := by
  obtain ⟨want_os, want_arch, want_variant⟩ := asks
  have table : Acceptable want.arch.val want.variant.val =
      [Text "v7", Text "v6", Text "v5", []] := by
    rw [want_arch, want_variant]; decide
  apply the_best_and_first_entry_is_chosen entries want 2#usize 0
  · obtain ⟨entry, at_2, is_entry⟩ := the_entry_described_is_there entries _ described 2
      ("linux", "arm", "v7", true) rfl
    obtain ⟨os, arch, variant, image⟩ := is_entry
    refine ⟨entry, at_2, image, ?_, ?_, ?_⟩
    · rw [os, want_os]
    · rw [arch, want_arch]
    · rw [table, variant]; rfl
  · intro j l ⟨entry, at_j, image, os, arch, in_table⟩
    obtain ⟨d, at_d, is_entry⟩ := the_entry_is_the_one_described entries _ described j entry at_j
    obtain ⟨os', arch', variant', image'⟩ := is_entry
    rw [table] at in_table
    refine ⟨Nat.zero_le l, fun zero => ?_⟩
    subst zero
    rcases j with _ | _ | _ | _ | j <;> simp at at_d <;> subst at_d <;> simp at in_table variant'
    · rw [variant'] at in_table; exact absurd in_table (by decide)
    · rw [variant'] at in_table; exact absurd in_table (by decide)
    · simp
    · rw [variant'] at in_table; exact absurd in_table (by decide)

/-- `arm` with `v6` against the entries v5, v6, v7, v8 takes v6, the second. -/
theorem arm_v6_takes_v6 (entries : Slice Entry) (want : Platform)
    (described : Describes entries [("linux", "arm", "v5", true), ("linux", "arm", "v6", true),
      ("linux", "arm", "v7", true), ("linux", "arm", "v8", true)])
    (asks : Asks want "linux" "arm" "v6") : choose entries want ⦃ r => r = some 1#usize ⦄ := by
  obtain ⟨want_os, want_arch, want_variant⟩ := asks
  have table : Acceptable want.arch.val want.variant.val = [Text "v6", Text "v5", []] := by
    rw [want_arch, want_variant]; decide
  apply the_best_and_first_entry_is_chosen entries want 1#usize 0
  · obtain ⟨entry, at_1, is_entry⟩ := the_entry_described_is_there entries _ described 1
      ("linux", "arm", "v6", true) rfl
    obtain ⟨os, arch, variant, image⟩ := is_entry
    refine ⟨entry, at_1, image, ?_, ?_, ?_⟩
    · rw [os, want_os]
    · rw [arch, want_arch]
    · rw [table, variant]; rfl
  · intro j l ⟨entry, at_j, image, os, arch, in_table⟩
    obtain ⟨d, at_d, is_entry⟩ := the_entry_is_the_one_described entries _ described j entry at_j
    obtain ⟨os', arch', variant', image'⟩ := is_entry
    rw [table] at in_table
    refine ⟨Nat.zero_le l, fun zero => ?_⟩
    subst zero
    rcases j with _ | _ | _ | _ | j <;> simp at at_d <;> subst at_d <;> simp at in_table variant'
    · rw [variant'] at in_table; exact absurd in_table (by decide)
    · simp
    · rw [variant'] at in_table; exact absurd in_table (by decide)
    · rw [variant'] at in_table; exact absurd in_table (by decide)

/-- `arm` with no variant against the entries v5, v6, v7, v8 takes v8, the fourth: no entry is
without a variant, and v8 is the best of the known ones. -/
theorem arm_without_a_variant_takes_v8 (entries : Slice Entry) (want : Platform)
    (described : Describes entries [("linux", "arm", "v5", true), ("linux", "arm", "v6", true),
      ("linux", "arm", "v7", true), ("linux", "arm", "v8", true)])
    (asks : Asks want "linux" "arm" "") : choose entries want ⦃ r => r = some 3#usize ⦄ := by
  obtain ⟨want_os, want_arch, want_variant⟩ := asks
  have table : Acceptable want.arch.val want.variant.val =
      [[], Text "v8", Text "v7", Text "v6", Text "v5"] := by
    rw [want_arch, want_variant]; decide
  apply the_best_and_first_entry_is_chosen entries want 3#usize 1
  · obtain ⟨entry, at_3, is_entry⟩ := the_entry_described_is_there entries _ described 3
      ("linux", "arm", "v8", true) rfl
    obtain ⟨os, arch, variant, image⟩ := is_entry
    refine ⟨entry, at_3, image, ?_, ?_, ?_⟩
    · rw [os, want_os]
    · rw [arch, want_arch]
    · rw [table, variant]; rfl
  · intro j l ⟨entry, at_j, image, os, arch, in_table⟩
    obtain ⟨d, at_d, is_entry⟩ := the_entry_is_the_one_described entries _ described j entry at_j
    obtain ⟨os', arch', variant', image'⟩ := is_entry
    rw [table] at in_table
    rcases l with _ | _ | l
    · -- no variant: none of the entries is without one
      simp at in_table
      rcases j with _ | _ | _ | _ | j <;> simp at at_d <;> subst at_d <;> simp at variant' <;>
        rw [variant'] at in_table <;> exact absurd in_table (by decide)
    · -- v8: only the fourth entry has it
      refine ⟨le_refl _, fun _ => ?_⟩
      simp at in_table
      rcases j with _ | _ | _ | _ | j <;> simp at at_d <;> subst at_d <;> simp at variant'
      · rw [variant'] at in_table; exact absurd in_table (by decide)
      · rw [variant'] at in_table; exact absurd in_table (by decide)
      · rw [variant'] at in_table; exact absurd in_table (by decide)
      · simp
    · exact ⟨by omega, fun same => by omega⟩

/-- `arm64` with `v8` against one entry without a variant takes it. -/
theorem arm64_v8_takes_an_entry_without_a_variant (entries : Slice Entry) (want : Platform)
    (described : Describes entries [("linux", "arm64", "", true)])
    (asks : Asks want "linux" "arm64" "v8") : choose entries want ⦃ r => r = some 0#usize ⦄ := by
  obtain ⟨want_os, want_arch, want_variant⟩ := asks
  have table : Acceptable want.arch.val want.variant.val = [Text "v8", []] := by
    rw [want_arch, want_variant]; decide
  apply the_best_and_first_entry_is_chosen entries want 0#usize 1
  · obtain ⟨entry, at_0, is_entry⟩ := the_entry_described_is_there entries _ described 0
      ("linux", "arm64", "", true) rfl
    obtain ⟨os, arch, variant, image⟩ := is_entry
    refine ⟨entry, at_0, image, ?_, ?_, ?_⟩
    · rw [os, want_os]
    · rw [arch, want_arch]
    · rw [table, variant]; rfl
  · intro j l ⟨entry, at_j, image, os, arch, in_table⟩
    obtain ⟨d, at_d, is_entry⟩ := the_entry_is_the_one_described entries _ described j entry at_j
    obtain ⟨os', arch', variant', image'⟩ := is_entry
    rw [table] at in_table
    rcases l with _ | _ | l
    · simp at in_table
      rcases j with _ | j
      · simp at at_d; subst at_d; simp at variant'
        rw [variant'] at in_table; exact absurd in_table (by decide)
      · simp at at_d
    · rcases j with _ | j <;> simp at at_d
      exact ⟨le_refl _, fun _ => Nat.zero_le _⟩
    · exact ⟨by omega, fun same => by omega⟩

/-- `arm64` with no variant against one entry of `v8` takes it. -/
theorem arm64_without_a_variant_takes_v8 (entries : Slice Entry) (want : Platform)
    (described : Describes entries [("linux", "arm64", "v8", true)])
    (asks : Asks want "linux" "arm64" "") : choose entries want ⦃ r => r = some 0#usize ⦄ := by
  obtain ⟨want_os, want_arch, want_variant⟩ := asks
  have table : Acceptable want.arch.val want.variant.val = [[], Text "v8"] := by
    rw [want_arch, want_variant]; decide
  apply the_best_and_first_entry_is_chosen entries want 0#usize 1
  · obtain ⟨entry, at_0, is_entry⟩ := the_entry_described_is_there entries _ described 0
      ("linux", "arm64", "v8", true) rfl
    obtain ⟨os, arch, variant, image⟩ := is_entry
    refine ⟨entry, at_0, image, ?_, ?_, ?_⟩
    · rw [os, want_os]
    · rw [arch, want_arch]
    · rw [table, variant]; rfl
  · intro j l ⟨entry, at_j, image, os, arch, in_table⟩
    obtain ⟨d, at_d, is_entry⟩ := the_entry_is_the_one_described entries _ described j entry at_j
    obtain ⟨os', arch', variant', image'⟩ := is_entry
    rw [table] at in_table
    rcases l with _ | _ | l
    · simp at in_table
      rcases j with _ | j
      · simp at at_d; subst at_d; simp at variant'
        rw [variant'] at in_table; exact absurd in_table (by decide)
      · simp at at_d
    · rcases j with _ | j <;> simp at at_d
      exact ⟨le_refl _, fun _ => Nat.zero_le _⟩
    · exact ⟨by omega, fun same => by omega⟩

/-- An attestation of the platform asked for is skipped for the image after it. -/
theorem an_attestation_is_skipped (entries : Slice Entry) (want : Platform)
    (described : Describes entries [("linux", "amd64", "", false), ("linux", "amd64", "", true)])
    (asks : Asks want "linux" "amd64" "") : choose entries want ⦃ r => r = some 1#usize ⦄ := by
  obtain ⟨want_os, want_arch, want_variant⟩ := asks
  have table : Acceptable want.arch.val want.variant.val = [[]] := by
    rw [want_arch, want_variant]; decide
  apply the_best_and_first_entry_is_chosen entries want 1#usize 0
  · obtain ⟨entry, at_1, is_entry⟩ := the_entry_described_is_there entries _ described 1
      ("linux", "amd64", "", true) rfl
    obtain ⟨os, arch, variant, image⟩ := is_entry
    refine ⟨entry, at_1, image, ?_, ?_, ?_⟩
    · rw [os, want_os]
    · rw [arch, want_arch]
    · rw [table, variant]; rfl
  · intro j l ⟨entry, at_j, image, os, arch, in_table⟩
    obtain ⟨d, at_d, is_entry⟩ := the_entry_is_the_one_described entries _ described j entry at_j
    obtain ⟨os', arch', variant', image'⟩ := is_entry
    refine ⟨Nat.zero_le l, fun zero => ?_⟩
    rcases j with _ | _ | j <;> simp at at_d <;> subst at_d
    · -- the attestation is not an image
      rw [image'] at image; exact absurd image (by decide)
    · simp

/-- An index of an attestation alone gives nothing, even for the platform it names. -/
theorem an_attestation_alone_is_not_taken (entries : Slice Entry) (want : Platform)
    (described : Describes entries [("unknown", "unknown", "", false)]) :
    choose entries want ⦃ r => r = none ⦄ := by
  apply nothing_is_chosen_from_attestations
  intro entry is_there
  obtain ⟨j, at_j⟩ := List.mem_iff_getElem?.mp is_there
  obtain ⟨d, at_d, _, _, _, image⟩ :=
    the_entry_is_the_one_described entries _ described j entry at_j
  rcases j with _ | j <;> simp at at_d
  subst at_d
  exact image

/-- The table is computed from its definition; each choice is one of the theorems above. -/
theorem worked_examples : WorkedExamples :=
  ⟨by decide, by decide, by decide, by decide, by decide, by decide,
   fun entries want described =>
     ⟨fun asks => arm_v7_takes_v7 entries want described asks,
      fun asks => arm_v6_takes_v6 entries want described asks,
      fun asks => arm_without_a_variant_takes_v8 entries want described asks⟩,
   fun entries want described asks =>
     arm64_v8_takes_an_entry_without_a_variant entries want described asks,
   fun entries want described asks => arm64_without_a_variant_takes_v8 entries want described asks,
   fun entries want described asks => an_attestation_is_skipped entries want described asks,
   fun entries want described _ => an_attestation_alone_is_not_taken entries want described⟩

end PlatformCore
