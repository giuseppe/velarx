-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what the small functions of the crate answer about the variants known of an
-- architecture: `known_len` (how many), `known_at` (the `i`-th, best first) and `is_wanted` (a
-- variant is one of the acceptable ones), each read as the lists of Spec.lean (`Known`,
-- `WantedBytes`).
-- Why it is needed: `wanted_variant` and `rank` are built on them, and the claims about the table
-- read them as lists.
-- Read before this file: Spec.lean, TheSameBytes.lean.
-- Notation: `f x ⦃ r => P r ⦄` reads: the Rust function `f`, given `x`, returns and its answer `r`
-- satisfies `P r`.  `step` goes through one line of the Rust function; `l[i]?` is `some` of the
-- element at the place `i` of the list `l`, or `none`.
import PlatformCore.TheSameBytes

open Aeneas Aeneas.Std Result velarx_platform_core

namespace PlatformCore

/-- The letters of `arm`, as the bytes the Rust function compares with. -/
theorem text_arm : Text "arm" = [97#u8, 114#u8, 109#u8] := rfl
/-- The letters of `arm64`. -/
theorem text_arm64 : Text "arm64" = [97#u8, 114#u8, 109#u8, 54#u8, 52#u8] := rfl
/-- The letters of `v8`. -/
theorem text_v8 : Text "v8" = [118#u8, 56#u8] := rfl
/-- The letters of `v7`. -/
theorem text_v7 : Text "v7" = [118#u8, 55#u8] := rfl
/-- The letters of `v6`. -/
theorem text_v6 : Text "v6" = [118#u8, 54#u8] := rfl
/-- The letters of `v5`. -/
theorem text_v5 : Text "v5" = [118#u8, 53#u8] := rfl

/-- **A comparison with a word written in the code**: `same` of a slice and of an array of bytes
answers true exactly when the slice is those bytes. -/
@[step]
theorem same_a_word (a : Slice Std.U8) (n : Std.Usize) (word : List Std.U8)
    (length : word.length = n.val) :
    same a (Array.make n word length).to_slice ⦃ r => r = true ↔ a.val = word ⦄ := by
  refine WP.spec_mono (same_is_equal a _) ?_
  intro r answer
  rw [answer]
  simp [Array.to_slice, Array.make]

/-- The variants known of `arm` are v8, v7, v6, v5. -/
theorem known_of_arm {arch : List Std.U8} (is_arm : arch = Text "arm") :
    Known arch = [Text "v8", Text "v7", Text "v6", Text "v5"] := by
  simp [Known, is_arm]

/-- The one variant known of `arm64` is v8. -/
theorem known_of_arm64 {arch : List Std.U8} (is_arm64 : arch = Text "arm64") :
    Known arch = [Text "v8"] := by
  have not_arm : Text "arm64" ≠ Text "arm" := by decide
  simp [Known, is_arm64, not_arm]

/-- No variant is known of any other architecture. -/
theorem known_of_another {arch : List Std.U8} (not_arm : arch ≠ Text "arm")
    (not_arm64 : arch ≠ Text "arm64") : Known arch = [] := by
  simp [Known, not_arm, not_arm64]

/-- **`known_len` is the number of variants known of the architecture** (`Known`); it returns. -/
@[step]
theorem known_len_is (arch : Slice Std.U8) :
    known_len arch ⦃ n => n.val = (Known arch.val).length ⦄ := by
  unfold known_len
  simp only [lift]
  step as ⟨ is_arm, arm_answer ⟩
  rw [← text_arm] at arm_answer
  by_cases arm : is_arm = true
  · -- `arm`: four variants
    simp only [arm, ↓reduceIte]
    refine (WP.spec_ok _).mpr ?_
    simp [known_of_arm (arm_answer.mp arm)]
  · simp only [arm, Bool.false_eq_true, ↓reduceIte]
    step as ⟨ is_arm64, arm64_answer ⟩
    rw [← text_arm64] at arm64_answer
    have not_arm : arch.val ≠ Text "arm" := fun same => arm (arm_answer.mpr same)
    by_cases arm64 : is_arm64 = true
    · -- `arm64`: one variant
      simp only [arm64, ↓reduceIte]
      refine (WP.spec_ok _).mpr ?_
      simp [known_of_arm64 (arm64_answer.mp arm64)]
    · -- any other: none
      simp only [arm64, Bool.false_eq_true, ↓reduceIte]
      refine (WP.spec_ok _).mpr ?_
      have not_arm64 : arch.val ≠ Text "arm64" := fun same => arm64 (arm64_answer.mpr same)
      simp [known_of_another not_arm not_arm64]

/-- **`known_at`** answers v8 for `arm64` whatever the place, and for another architecture v8, v7,
v6, v5 for the places 0, 1, 2 and 3 or more; it is never `Asked`, and it returns. -/
@[step]
theorem known_at_answers (arch : Slice Std.U8) (i : Std.Usize) :
    known_at arch i ⦃ w =>
      (arch.val = Text "arm64" → w = Wanted.V8) ∧
      (arch.val ≠ Text "arm64" →
        (i.val = 0 → w = Wanted.V8) ∧ (i.val = 1 → w = Wanted.V7) ∧
        (i.val = 2 → w = Wanted.V6) ∧ (3 ≤ i.val → w = Wanted.V5)) ⦄ := by
  unfold known_at
  simp only [lift]
  step as ⟨ is_arm64, arm64_answer ⟩
  rw [← text_arm64] at arm64_answer
  by_cases arm64 : is_arm64 = true
  · simp only [arm64, ↓reduceIte]
    refine (WP.spec_ok _).mpr
      ⟨fun _ => rfl, fun not_arm64 => absurd (arm64_answer.mp arm64) not_arm64⟩
  · simp only [arm64, Bool.false_eq_true, ↓reduceIte]
    have not_arm64 : arch.val ≠ Text "arm64" := fun same => arm64 (arm64_answer.mpr same)
    by_cases first : i = 0#usize
    · simp only [first, ↓reduceIte]
      refine (WP.spec_ok _).mpr ⟨fun same => absurd same not_arm64, fun _ => ?_⟩
      subst first
      simp
    by_cases second : i = 1#usize
    · simp only [second, ↓reduceIte]
      refine (WP.spec_ok _).mpr ⟨fun same => absurd same not_arm64, fun _ => ?_⟩
      subst second
      simp
    by_cases third : i = 2#usize
    · simp only [third, ↓reduceIte]
      refine (WP.spec_ok _).mpr ⟨fun same => absurd same not_arm64, fun _ => ?_⟩
      subst third
      simp
    · simp only [first, second, third, ↓reduceIte]
      refine (WP.spec_ok _).mpr ⟨fun same => absurd same not_arm64, fun _ => ?_⟩
      have after : 3 ≤ i.val := by scalar_tac
      simp [after]
      omega

/-- The `i`-th known variant of an architecture, by the places `known_at` answers for: the `i`-th
of `Known` is what `w` stands for. -/
theorem known_by_place (arch : List Std.U8) (i : Nat) (w : Wanted) (asked : List Std.U8)
    (below : i < (Known arch).length)
    (answers : (arch = Text "arm64" → w = Wanted.V8) ∧
      (arch ≠ Text "arm64" →
        (i = 0 → w = Wanted.V8) ∧ (i = 1 → w = Wanted.V7) ∧
        (i = 2 → w = Wanted.V6) ∧ (3 ≤ i → w = Wanted.V5))) :
    (Known arch)[i]? = some (WantedBytes asked w) := by
  by_cases arm64 : arch = Text "arm64"
  · rw [answers.1 arm64, known_of_arm64 arm64]
    rw [known_of_arm64 arm64] at below
    simp at below
    simp [below, WantedBytes]
  · by_cases arm : arch = Text "arm"
    · obtain ⟨zero, one, two, more⟩ := answers.2 arm64
      rw [known_of_arm arm] at below ⊢
      simp only [List.length_cons, List.length_nil] at below
      rcases (by omega : i = 0 ∨ i = 1 ∨ i = 2 ∨ i = 3) with is_i | is_i | is_i | is_i
      · subst is_i; simp [zero rfl, WantedBytes]
      · subst is_i; simp [one rfl, WantedBytes]
      · subst is_i; simp [two rfl, WantedBytes]
      · subst is_i; simp [more (by omega), WantedBytes]
    · rw [known_of_another arm arm64] at below
      simp at below

/-- **`is_wanted` says whether a variant is the acceptable one** `w`, for a request that names
`asked`: `variant` is exactly the bytes that `w` stands for (`WantedBytes`); it returns. -/
@[step]
theorem is_wanted_is (w : Wanted) (asked variant : Slice Std.U8) :
    is_wanted w asked variant ⦃ r => r = true ↔ variant.val = WantedBytes asked.val w ⦄ := by
  unfold is_wanted
  simp only [lift]
  cases w
  · -- no variant: the slice is empty
    step as ⟨ empty, is_empty ⟩
    simp [is_empty, WantedBytes]
  · step as ⟨ r, is_r ⟩
    simp [WantedBytes, is_r, text_v8]
  · step as ⟨ r, is_r ⟩
    simp [WantedBytes, is_r, text_v7]
  · step as ⟨ r, is_r ⟩
    simp [WantedBytes, is_r, text_v6]
  · step as ⟨ r, is_r ⟩
    simp [WantedBytes, is_r, text_v5]
  · -- the variant that was asked
    step as ⟨ r, is_r ⟩
    simp [WantedBytes, is_r]

end PlatformCore
