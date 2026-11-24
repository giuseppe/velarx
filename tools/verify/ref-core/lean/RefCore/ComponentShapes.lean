-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: how a component of a path is made, read from left to right: what its
-- beginning can be (`ComponentSoFar`: nothing, a component, or a component and a separator with a
-- letter or a digit next) and what a run of one byte is when it is a separator. It also shows what
-- can follow the first byte of a component (`ComponentTail`).
-- Why it is needed: `component_bad` reads a component and jumps over each run of one separator;
-- this is the proof that doing so reads exactly the components of Spec.lean (`Component`).
-- Read before this file: Spec.lean (`Component`, `IsSeparator`), Pieces.lean.
-- Notation: `∃ x, P x` is "there is an x such that P x".
import RefCore.Pieces
namespace RefCore

/-- A component with one more letter or digit is a component. -/
theorem component_snoc_alnum {c : List Nat} (is_component : Component c) {b : Nat}
    (alnum : IsAlnum b) : Component (c ++ [b]) := by
  cases is_component with
  | word is_word =>
    refine Component.word ⟨by simp, fun x inside => ?_⟩
    rcases List.mem_append.mp inside with old | new
    · exact is_word.2 x old
    · rw [List.mem_singleton.mp new]; exact alnum
  | join old sep is_word =>
    have more : Alnums (_ ++ [b]) := ⟨by simp, fun x inside => by
      rcases List.mem_append.mp inside with old | new
      · exact is_word.2 x old
      · rw [List.mem_singleton.mp new]; exact alnum⟩
    simpa [List.append_assoc] using Component.join old sep more

/-- What the beginning of a component can be, read from left to right: nothing, a component, or a
component and a separator, with a letter or a digit after it in the text (the separator is not
the last of the component). -/
def ComponentSoFar (text : List Nat) (start stop limit : Nat) : Prop :=
  Piece text start stop = [] ∨ Component (Piece text start stop) ∨
    ∃ c sep, Component c ∧ IsSeparator sep ∧ Piece text start stop = c ++ sep ∧
      stop < limit ∧ ∃ x, text[stop]? = some x ∧ IsAlnum x

/-- A letter or a digit continues the beginning of a component. -/
theorem so_far_then_a_letter {c : List Nat} {b : Nat} (alnum : IsAlnum b)
    (text : List Nat) (start stop limit : Nat) (so_far : ComponentSoFar text start stop limit)
    (is_c : Piece text start stop = c) : Component (c ++ [b]) := by
  rcases so_far with empty | whole | ⟨d, sep, is_d, is_sep, split, _, _⟩
  · rw [empty] at is_c; subst is_c
    exact Component.word ⟨by simp, fun x inside => by
      have same : x = b := by simpa using inside
      rw [same]; exact alnum⟩
  · rw [is_c] at whole
    exact component_snoc_alnum whole alnum
  · rw [is_c] at split; subst split
    exact Component.join is_d is_sep ⟨by simp, fun x inside => by
      have same : x = b := by simpa using inside
      rw [same]; exact alnum⟩

/-- A run of the same byte is a separator when the byte is `-`, or `.` once, or `_` once or
twice. -/
theorem run_is_a_separator (b run : Nat) (not_empty : 1 ≤ run)
    (allowed : b = 45 ∨ (b = 46 ∧ run = 1) ∨ (b = 95 ∧ run ≤ 2)) :
    IsSeparator (List.replicate run b) := by
  rcases allowed with hyphen | ⟨dot, once⟩ | ⟨underscore, twice⟩
  · exact Or.inr (Or.inr (Or.inr ⟨by simp; omega, fun x inside => by
      have := (List.mem_replicate.mp inside).2
      omega⟩))
  · subst dot; subst once; exact Or.inl rfl
  · subst underscore
    rcases (by omega : run = 1 ∨ run = 2) with once | twice
    · subst once; exact Or.inr (Or.inl rfl)
    · subst twice; exact Or.inr (Or.inr (Or.inl rfl))

/-- What can follow the first letter or digit of a component, read from left to right: nothing, or a
letter or a digit and then what can follow, or a separator, a letter or a digit and then what can
follow. -/
inductive ComponentTail : List Nat → Prop
  | nil : ComponentTail []
  | letter {b : Nat} {rest : List Nat} : IsAlnum b → ComponentTail rest → ComponentTail (b :: rest)
  | separated {sep rest : List Nat} {b : Nat} : IsSeparator sep → IsAlnum b → ComponentTail rest →
      ComponentTail (sep ++ b :: rest)

/-- What can follow is empty, or begins with a letter or a digit, or with a separator and then a
letter or a digit. -/
theorem tail_cases {l : List Nat} (tail : ComponentTail l) :
    l = [] ∨ (∃ b rest, l = b :: rest ∧ IsAlnum b ∧ ComponentTail rest) ∨
      ∃ sep b rest, l = sep ++ b :: rest ∧ IsSeparator sep ∧ IsAlnum b ∧ ComponentTail rest := by
  cases tail with
  | nil => exact Or.inl rfl
  | letter alnum more => exact Or.inr (Or.inl ⟨_, _, rfl, alnum, more⟩)
  | separated sep alnum more => exact Or.inr (Or.inr ⟨_, _, _, rfl, sep, alnum, more⟩)

/-- What can follow, and then what can follow, can follow. -/
theorem tail_append {x y : List Nat} (first : ComponentTail x) (second : ComponentTail y) :
    ComponentTail (x ++ y) := by
  induction first with
  | nil => simpa using second
  | letter alnum more ih => exact ComponentTail.letter alnum ih
  | separated sep alnum more ih =>
    rw [List.append_assoc]
    exact ComponentTail.separated sep alnum (by simpa using ih)

/-- A word of letters and digits can follow. -/
theorem tail_of_a_word {w : List Nat} (all : ∀ b ∈ w, IsAlnum b) : ComponentTail w := by
  induction w with
  | nil => exact ComponentTail.nil
  | cons b rest ih =>
    exact ComponentTail.letter (all b (by simp)) (ih fun x inside => all x (by simp [inside]))

/-- A separator and a word of letters and digits that is not empty can follow. -/
theorem tail_of_a_separator_and_a_word {sep w : List Nat} (is_sep : IsSeparator sep)
    (word : Alnums w) : ComponentTail (sep ++ w) := by
  obtain ⟨not_empty, all⟩ := word
  cases w with
  | nil => exact absurd rfl not_empty
  | cons b rest =>
    exact ComponentTail.separated is_sep (all b (by simp))
      (tail_of_a_word fun x inside => all x (by simp [inside]))

/-- What a component is, as what can follow: all of it can follow. -/
theorem component_is_a_tail {c : List Nat} (is_component : Component c) : ComponentTail c := by
  induction is_component with
  | word word => exact tail_of_a_word word.2
  | join old is_sep word ih =>
    rw [List.append_assoc]
    exact tail_append ih (tail_of_a_separator_and_a_word is_sep word)

/-- A separator is not empty and has one byte only, a `.`, a `_` or a `-`. -/
theorem separator_is_a_run {sep : List Nat} (is_sep : IsSeparator sep) :
    ∃ x m, sep = List.replicate m x ∧ 1 ≤ m ∧ (x = 45 ∨ (x = 46 ∧ m = 1) ∨ (x = 95 ∧ m ≤ 2)) := by
  rcases is_sep with dot | under | under2 | ⟨not_empty, hyphens⟩
  · exact ⟨46, 1, by rw [dot]; rfl, le_refl _, Or.inr (Or.inl ⟨rfl, rfl⟩)⟩
  · exact ⟨95, 1, by rw [under]; rfl, le_refl _, Or.inr (Or.inr ⟨rfl, by omega⟩)⟩
  · exact ⟨95, 2, by rw [under2]; rfl, by omega, Or.inr (Or.inr ⟨rfl, le_refl _⟩)⟩
  · refine ⟨45, sep.length, ?_, List.length_pos_iff.mpr not_empty, Or.inl rfl⟩
    exact (List.eq_replicate_iff.mpr ⟨rfl, hyphens⟩)

/-- The last byte of a word of letters and digits that is not empty is a letter or a digit. -/
theorem word_ends_in_alnum {w : List Nat} (word : Alnums w) :
    ∃ z, w.getLast? = some z ∧ IsAlnum z := by
  obtain ⟨not_empty, all⟩ := word
  obtain ⟨z, z_is⟩ := Option.isSome_iff_exists.mp (List.getLast?_isSome.mpr not_empty)
  exact ⟨z, z_is, all z (List.mem_of_getLast? z_is)⟩

/-- A component ends in a letter or a digit. -/
theorem component_ends_in_alnum {c : List Nat} (is_component : Component c) :
    ∃ z, c.getLast? = some z ∧ IsAlnum z := by
  induction is_component with
  | word word => exact word_ends_in_alnum word
  | join old sep word ih =>
    obtain ⟨z, z_is, z_alnum⟩ := word_ends_in_alnum word
    refine ⟨z, ?_, z_alnum⟩
    rw [List.getLast?_append_of_ne_nil _ word.1]
    exact z_is

end RefCore
