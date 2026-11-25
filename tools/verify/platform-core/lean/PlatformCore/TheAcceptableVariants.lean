-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `wanted_variant` answers, as the table `Acceptable` of Spec.lean: the
-- k-th answer is the k-th acceptable variant, and none past the last.  It also shows that the
-- known variants and the acceptable ones have no repeats, which is why an entry matches one
-- acceptable platform at most.
-- Why it is needed: `rank` reads `wanted_variant` place by place, and the claims about what is
-- chosen are about the table.
-- Read before this file: Spec.lean, TheVariantsOfAnArchitecture.lean.
-- Notation: `f x ⦃ r => P r ⦄` reads: the Rust function `f`, given `x`, returns and its answer `r`
-- satisfies `P r`.  `l[i]?` is `some` of the element at the place `i` of the list `l`, or `none`;
-- `l.Nodup` is "no two elements of `l` are equal"; `l.idxOf x` is the place of `x` in `l`.
import PlatformCore.TheVariantsOfAnArchitecture

open Aeneas Aeneas.Std Result velarx_platform_core

namespace PlatformCore

/-- No variant is known twice of an architecture. -/
theorem known_has_no_repeats (arch : List Std.U8) : (Known arch).Nodup := by
  by_cases arm : arch = Text "arm"
  · rw [known_of_arm arm]; decide
  · by_cases arm64 : arch = Text "arm64"
    · rw [known_of_arm64 arm64]; decide
    · rw [known_of_another arm arm64]; exact List.nodup_nil

/-- A known variant is a name, not "no variant". -/
theorem known_variants_are_names (arch : List Std.U8) : ∀ v ∈ Known arch, v ≠ [] := by
  by_cases arm : arch = Text "arm"
  · rw [known_of_arm arm]; decide
  · by_cases arm64 : arch = Text "arm64"
    · rw [known_of_arm64 arm64]; decide
    · rw [known_of_another arm arm64]; simp

/-- The acceptable variants of a request are all different: so a variant is at one place of the
table at most. -/
theorem acceptable_has_no_repeats (arch variant : List Std.U8) :
    (Acceptable arch variant).Nodup := by
  have names := known_variants_are_names arch
  unfold Acceptable
  by_cases none_asked : variant = []
  · -- no variant first, then the known ones (which are names)
    simp only [none_asked, ↓reduceIte]
    exact List.nodup_cons.mpr ⟨fun absent => names [] absent rfl, known_has_no_repeats arch⟩
  · simp only [none_asked, ↓reduceIte]
    by_cases known : variant ∈ Known arch
    · -- the variant and the known ones below it, then no variant
      simp only [known, ↓reduceIte]
      refine List.nodup_append.mpr ⟨?_, List.nodup_singleton _, ?_⟩
      · exact (known_has_no_repeats arch).sublist (List.drop_sublist _ _)
      · intro v in_drop w in_last
        rw [List.mem_singleton] at in_last
        subst in_last
        exact names v (List.mem_of_mem_drop in_drop)
    · -- a variant that is not known, then no variant
      simp only [known, ↓reduceIte]
      exact List.nodup_cons.mpr ⟨by simpa using none_asked, List.nodup_singleton _⟩

/-- **The loop of `wanted_variant`** goes up the known variants from the place `at0` and stops at
the first one that is the variant asked, or at the end: the place it answers is at most `n`, no
known variant before it is the variant asked, and the one at it is, unless it is the end. -/
theorem wanted_variant_loop_finds (arch variant : Slice Std.U8) (n at0 : Std.Usize)
    (is_n : n.val = (Known arch.val).length) (before_the_end : at0.val ≤ n.val)
    (none_before : ∀ j, j < at0.val → (Known arch.val)[j]? ≠ some variant.val) :
    wanted_variant_loop arch variant n at0 ⦃ r =>
      r.val ≤ n.val ∧ (∀ j, j < r.val → (Known arch.val)[j]? ≠ some variant.val) ∧
      (r.val < n.val → (Known arch.val)[r.val]? = some variant.val) ⦄ := by
  unfold wanted_variant_loop
  apply loop.spec_decr_nat (fun (q : Std.Usize) => n.val - q.val)
    (fun (q : Std.Usize) =>
      q.val ≤ n.val ∧ ∀ j, j < q.val → (Known arch.val)[j]? ≠ some variant.val)
  · intro at' ⟨before_the_end', none_before'⟩
    unfold wanted_variant_loop.body
    by_cases inside : at' < n
    · -- a known variant is left: it is compared with the variant asked
      simp only [inside, ↓reduceIte]
      step as ⟨ w, w_arm64, w_another ⟩
      step as ⟨ same, is_same ⟩
      have inside' : at'.val < (Known arch.val).length := by scalar_tac
      have at_at := known_by_place arch.val at'.val w variant.val inside'
        ⟨w_arm64, w_another⟩
      by_cases found : same = true
      · -- it is the variant asked: the loop stops here
        simp only [found, ↓reduceIte]
        refine (WP.spec_ok _).mpr ⟨before_the_end', none_before', fun _ => ?_⟩
        rw [at_at, ← is_same.mp found]
      · -- it is not: the loop goes on
        simp only [found, Bool.false_eq_true, ↓reduceIte]
        step as ⟨ at2, is_at2 ⟩
        refine ⟨by scalar_tac, fun j below => ?_, by scalar_tac⟩
        rcases Nat.lt_succ_iff_lt_or_eq.mp (by omega : j < at'.val + 1) with earlier | here
        · exact none_before' j earlier
        · rw [here, at_at]
          intro same_variant
          injection same_variant with same_variant
          exact found (is_same.mpr same_variant.symm)
    · -- the end: the loop stops
      simp only [inside, ↓reduceIte]
      refine (WP.spec_ok _).mpr ⟨before_the_end', none_before', fun below => ?_⟩
      scalar_tac
  · exact ⟨before_the_end, none_before⟩

/-- At most four variants are known of any architecture. -/
theorem at_most_four_are_known (arch : List Std.U8) : (Known arch).length ≤ 4 := by
  by_cases arm : arch = Text "arm"
  · rw [known_of_arm arm]; decide
  · by_cases arm64 : arch = Text "arm64"
    · rw [known_of_arm64 arm64]; decide
    · rw [known_of_another arm arm64]; simp

/-- With no variant asked, the acceptable variants are none, then the known ones. -/
theorem acceptable_when_none_is_asked (arch : List Std.U8) :
    Acceptable arch [] = [] :: Known arch := by
  simp [Acceptable]

/-- With a known variant asked, the acceptable ones are it and the known ones below it, then
none. -/
theorem acceptable_when_a_known_one_is_asked (arch variant : List Std.U8)
    (is_name : variant ≠ []) (is_known : variant ∈ Known arch) :
    Acceptable arch variant = (Known arch).drop ((Known arch).idxOf variant) ++ [[]] := by
  simp [Acceptable, is_name, is_known]

/-- With a variant asked that is not known, the acceptable ones are it, then none. -/
theorem acceptable_when_an_unknown_one_is_asked (arch variant : List Std.U8)
    (is_name : variant ≠ []) (unknown : variant ∉ Known arch) :
    Acceptable arch variant = [variant, []] := by
  simp [Acceptable, is_name, unknown]

/-- **`wanted_variant` is the table** `Acceptable`: its `k`-th answer stands for the `k`-th
acceptable variant, and it answers none past the last.  It returns for every `k` that has room
to add the four places it may add. -/
theorem wanted_variant_answers_the_table (arch variant : Slice Std.U8) (k : Std.Usize)
    (room : HasRoom k) :
    wanted_variant arch variant k ⦃ r =>
      r.map (WantedBytes variant.val) = (Acceptable arch.val variant.val)[k.val]? ⦄ := by
  unfold wanted_variant
  have few := at_most_four_are_known arch.val
  have room' : k.val + 4 ≤ Std.Usize.max := room
  step as ⟨ n, is_n ⟩
  step as ⟨ none_asked, is_none_asked ⟩
  by_cases empty : none_asked = true
  · -- no variant asked: none, then the known variants
    simp only [empty, ↓reduceIte]
    have variant_is : variant.val = [] := by simpa [Slice.length] using is_none_asked.mp empty
    rw [variant_is, acceptable_when_none_is_asked]
    by_cases first : k = 0#usize
    · simp only [first, ↓reduceIte]
      refine (WP.spec_ok _).mpr ?_
      simp [WantedBytes]
    · simp only [first, ↓reduceIte]
      by_cases inside : k ≤ n
      · simp only [inside, ↓reduceIte]
        step as ⟨ i, is_i ⟩
        step as ⟨ w, w_arm64, w_another ⟩
        have below : i.val < (Known arch.val).length := by scalar_tac
        have at_i := known_by_place arch.val i.val w variant.val below ⟨w_arm64, w_another⟩
        rw [variant_is] at at_i
        have k_is : k.val = i.val + 1 := by scalar_tac
        simp only [Option.map_some]
        rw [k_is, List.getElem?_cons_succ, at_i]
      · simp only [inside, ↓reduceIte]
        refine (WP.spec_ok _).mpr ?_
        have outside : (Known arch.val).length < k.val := by scalar_tac
        simp [List.getElem?_eq_none (by simp; omega : ([] :: Known arch.val).length ≤ k.val)]
  · -- a variant asked: the loop finds where it is among the known ones
    simp only [empty, Bool.false_eq_true, ↓reduceIte]
    have is_name : variant.val ≠ [] := by
      intro none_there
      apply empty
      rw [is_none_asked]
      simpa [Slice.length] using none_there
    step with wanted_variant_loop_finds arch variant n 0#usize is_n (by scalar_tac)
      (fun j below => by simp at below) as ⟨ at_, at_le, none_before, at_is ⟩
    by_cases found : at_ < n
    · -- a known variant is the one asked: it and the ones below it, then none
      simp only [found, ↓reduceIte]
      have below : at_.val < (Known arch.val).length := by scalar_tac
      have at_at := at_is found
      have is_known : variant.val ∈ Known arch.val :=
        List.mem_of_getElem? at_at
      have place : (Known arch.val).idxOf variant.val = at_.val := by
        have := (known_has_no_repeats arch.val).idxOf_getElem at_.val below
        rwa [(List.getElem?_eq_some_iff.mp at_at).2] at this
      rw [acceptable_when_a_known_one_is_asked arch.val variant.val is_name is_known, place]
      step as ⟨ i, is_i ⟩
      by_cases inside : i < n
      · -- the variant is one of the known ones below: the one at `at_ + k`
        simp only [inside, ↓reduceIte]
        step as ⟨ i2, is_i2 ⟩
        step as ⟨ w, w_arm64, w_another ⟩
        have below_i2 : i2.val < (Known arch.val).length := by scalar_tac
        have at_i2 := known_by_place arch.val i2.val w variant.val below_i2
          ⟨w_arm64, w_another⟩
        simp only [Option.map_some]
        have in_drop : k.val < ((Known arch.val).drop at_.val).length := by
          simp only [List.length_drop]; scalar_tac
        rw [List.getElem?_append_left in_drop, List.getElem?_drop, ← at_i2]
        congr 2
      · simp only [inside, ↓reduceIte]
        by_cases last : i = n
        · -- the one after the last: no variant
          simp only [last, ↓reduceIte]
          refine (WP.spec_ok _).mpr ?_
          have k_is : k.val = ((Known arch.val).drop at_.val).length := by
            simp only [List.length_drop]; scalar_tac
          simp only [Option.map_some]
          rw [k_is, List.getElem?_append_right (le_refl _)]
          simp [WantedBytes]
        · -- past the last: nothing
          simp only [last, ↓reduceIte]
          refine (WP.spec_ok _).mpr ?_
          have past : ((Known arch.val).drop at_.val ++ [[]]).length ≤ k.val := by
            simp only [List.length_append, List.length_drop, List.length_singleton]; scalar_tac
          simp [List.getElem?_eq_none past]
    · -- no known variant is the one asked: it, then none
      simp only [found, ↓reduceIte]
      have unknown : variant.val ∉ Known arch.val := by
        intro is_known
        obtain ⟨j, at_j⟩ := List.mem_iff_getElem?.mp is_known
        have : j < (Known arch.val).length := (List.getElem?_eq_some_iff.mp at_j).1
        exact none_before j (by scalar_tac) at_j
      rw [acceptable_when_an_unknown_one_is_asked arch.val variant.val is_name unknown]
      by_cases first : k = 0#usize
      · simp only [first, ↓reduceIte]
        refine (WP.spec_ok _).mpr ?_
        simp [WantedBytes]
      · simp only [first, ↓reduceIte]
        by_cases second : k = 1#usize
        · simp only [second, ↓reduceIte]
          refine (WP.spec_ok _).mpr ?_
          simp [WantedBytes]
        · simp only [second, ↓reduceIte]
          refine (WP.spec_ok _).mpr ?_
          have : 2 ≤ k.val := by scalar_tac
          simp [List.getElem?_eq_none (by simp; omega : [variant.val, []].length ≤ k.val)]

end PlatformCore
