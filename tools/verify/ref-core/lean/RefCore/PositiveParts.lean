-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the bytes that an accepted host and an accepted path are made of, said
-- by what they may be and not by what they may not be (Safety.lean), and that no path has two `.`
-- next to each other.
-- Why it is needed: a reader of the claims sees the whole alphabet of a host and of a path in one
-- line; and a `..` in a path is what a file name would read as the parent directory.
-- Read before this file: Safety.lean, ParseComplete.lean.
-- Notation: `List.IsChain R l` is "`R` holds between every byte of `l` and the next one".
import RefCore.ParseComplete
open Aeneas Aeneas.Std Result velarx_ref_core
namespace RefCore

/-- Two bytes that are not both `.`. -/
def NotTwoDots (a b : Nat) : Prop := ¬ (a = 46 ∧ b = 46)

/-- A list with no `.` in it has no two `.` next to each other. -/
theorem no_dots_no_double_dot {l : List Nat} (none_ : ∀ b ∈ l, b ≠ 46) :
    List.IsChain NotTwoDots l := by
  rw [List.isChain_iff_getElem]
  intro i hi
  exact fun both => none_ _ (List.getElem_mem _) both.1

/-- A component has no two `.` next to each other. -/
theorem component_has_no_double_dot {c : List Nat} (is_component : Component c) :
    List.IsChain NotTwoDots c := by
  induction is_component with
  | word word =>
    exact no_dots_no_double_dot fun b inside same => by
      have := word.2 b inside
      unfold IsAlnum IsLower IsDigit at this
      omega
  | @join c sep w old is_sep word ih =>
    have alnum_not_dot : ∀ b, IsAlnum b → b ≠ 46 := fun b h same => by
      unfold IsAlnum IsLower IsDigit at h; omega
    have word_ok : List.IsChain NotTwoDots w :=
      no_dots_no_double_dot fun b inside => alnum_not_dot b (word.2 b inside)
    have sep_ok : List.IsChain NotTwoDots sep := by
      rcases is_sep with dot | under | under2 | ⟨_, hyphens⟩
      · subst dot; simp
      · subst under; simp
      · subst under2; simp [NotTwoDots]
      · exact no_dots_no_double_dot fun b inside same => by
          have := hyphens b inside; omega
    obtain ⟨z, z_is, z_alnum⟩ := component_ends_in_alnum old
    refine List.isChain_append.mpr ⟨List.isChain_append.mpr ⟨ih, sep_ok, ?_⟩, word_ok, ?_⟩
    · intro x x_is y _ both
      have same : x = z := by rw [z_is] at x_is; exact (Option.some.inj x_is).symm
      exact alnum_not_dot z z_alnum (same ▸ both.1)
    · intro x _ y y_is both
      exact alnum_not_dot y (word.2 y (List.mem_of_mem_head? y_is)) both.2

/-- A path has no two `.` next to each other. -/
theorem path_has_no_double_dot {p : List Nat} (is_path : Path p) : List.IsChain NotTwoDots p := by
  induction is_path with
  | one is_component => exact component_has_no_double_dot is_component
  | more old is_component ih =>
    refine List.isChain_append.mpr ⟨List.isChain_append.mpr ⟨ih, by simp, ?_⟩,
      component_has_no_double_dot is_component, ?_⟩
    · intro x _ y y_is both
      have := Option.mem_def.mp y_is
      simp at this
      omega
    · intro x x_is y _ both
      simp at x_is
      omega

/-- What an accepted host and an accepted path are made of, and that the path has no `..`. -/
theorem accepted_bytes_are_only_these : AcceptedBytesAreOnlyThese := fun s =>
  WP.spec_mono (parse_accepts_only_the_grammar s) (fun _ good spans is_ok => by
    have grammar := (good spans is_ok).1.1
    exact ⟨fun h is_h b inside => host_bytes (grammar.host h is_h).1 b inside,
      path_bytes grammar.path, path_has_no_double_dot grammar.path⟩)

end RefCore
