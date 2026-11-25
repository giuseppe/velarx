-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the claims of Spec.lean about names: the overlay names never get through, the
-- names of layers do, what is refused and what is the overlay's or the label exactly.
-- Why it is needed: Theorems.lean names what is proved; the proofs are here.  They are read off `class_answers`
-- (TheClass.lean), which says what `class` answers for every name.
-- Read before this file: Spec.lean, TheClass.lean.
-- Notation: `intro` takes the "for every" or the "if" of the goal as a given; `refine WP.spec_mono (class_answers
-- attr) ?_` says: `class` returns and what it answers is what `class_answers` says, from which the
-- claim follows; `rcases` splits a given "or" or "and"; `decide` computes a statement about fixed
-- lists.
import OverlayCore.TheClass

open Aeneas Aeneas.Std Result velarx_overlay_core
namespace OverlayCore

/-- An overlay name is a name that begins with one of the four words. -/
theorem overlay_name_iff_four (b : List Std.U8) :
    OverlayName b ↔ Text "trusted.overlay." <+: b ∨ Text "user.overlay." <+: b ∨
      Text "security.overlay." <+: b ∨ Text "system.overlay." <+: b := by
  have e1 : Text "trusted." ++ Text "overlay." = Text "trusted.overlay." := by decide
  have e2 : Text "user." ++ Text "overlay." = Text "user.overlay." := by decide
  have e3 : Text "security." ++ Text "overlay." = Text "security.overlay." := by decide
  have e4 : Text "system." ++ Text "overlay." = Text "system.overlay." := by decide
  constructor
  · rintro ⟨ns, member, begins⟩
    simp only [Namespaces, List.mem_cons, List.not_mem_nil, or_false] at member
    rcases member with rfl | rfl | rfl | rfl
    · exact Or.inl (e1 ▸ begins)
    · exact Or.inr (Or.inl (e2 ▸ begins))
    · exact Or.inr (Or.inr (Or.inl (e3 ▸ begins)))
    · exact Or.inr (Or.inr (Or.inr (e4 ▸ begins)))
  · rintro (begins | begins | begins | begins)
    · exact ⟨Text "trusted.", by simp [Namespaces], e1 ▸ begins⟩
    · exact ⟨Text "user.", by simp [Namespaces], e2 ▸ begins⟩
    · exact ⟨Text "security.", by simp [Namespaces], e3 ▸ begins⟩
    · exact ⟨Text "system.", by simp [Namespaces], e4 ▸ begins⟩

/-- A class is plain exactly when no other answer holds. -/
theorem plain_iff (bs : List Std.U8) (c : Class) (answers : ClassIs bs c) :
    c = Class.Plain ↔ bs ≠ [] ∧ 0#u8 ∉ bs ∧ bs ∉ Namespaces ∧ ¬ OverlayName bs ∧
      bs ≠ Text "security.selinux" := by
  obtain ⟨empty, nul, no_name, overlay, label⟩ := answers
  cases c with
  | Plain =>
    refine ⟨fun _ => ⟨?_, ?_, ?_, ?_, ?_⟩, fun _ => rfl⟩
    · intro nil; have := empty.mpr nil; simp at this
    · intro has_nul
      by_cases nil : bs = []
      · subst nil; simp at has_nul
      · have := nul.mpr ⟨nil, has_nul⟩; simp at this
    · intro member; have := no_name.mpr member; simp at this
    · intro is_overlay
      by_cases has_nul : 0#u8 ∈ bs
      · have : bs ≠ [] := by rintro rfl; simp at has_nul
        have := nul.mpr ⟨this, has_nul⟩; simp at this
      · have := overlay.mpr ⟨has_nul, is_overlay⟩; simp at this
    · intro is_label; have := label.mpr is_label; simp at this
  | Overlay =>
    constructor
    · intro h; simp at h
    · rintro ⟨_, has_nul, _, not_overlay, _⟩
      exact absurd (overlay.mp rfl).2 not_overlay
  | Label =>
    constructor
    · intro h; simp at h
    · rintro ⟨_, _, _, _, not_label⟩
      exact absurd (label.mp rfl) not_label
  | Refused why =>
    cases why
    · constructor
      · intro h; simp at h
      · rintro ⟨nonempty, _⟩; exact absurd (empty.mp rfl) nonempty
    · constructor
      · intro h; simp at h
      · rintro ⟨_, no_nul, _⟩; exact absurd (nul.mp rfl).2 no_nul
    · constructor
      · intro h; simp at h
      · rintro ⟨_, _, not_member, _⟩; exact absurd (no_name.mp rfl) not_member

/-- Proof of `NoOverlayNameGetsThrough`: a plain name is none of the other answers, and a name
that begins with one of the four words is an overlay name. -/
theorem no_overlay_name_gets_through : NoOverlayNameGetsThrough := by
  intro attr
  refine WP.spec_mono (class_answers attr) ?_
  intro c answers plain
  obtain ⟨_, _, _, not_overlay, not_label⟩ := (plain_iff attr.val c answers).mp plain
  have none_of_four := fun h => not_overlay ((overlay_name_iff_four attr.val).mpr h)
  exact ⟨fun h => none_of_four (Or.inl h), fun h => none_of_four (Or.inr (Or.inl h)),
    fun h => none_of_four (Or.inr (Or.inr (Or.inl h))),
    fun h => none_of_four (Or.inr (Or.inr (Or.inr h))), not_label⟩

/-- Proof of `TheNamesOfLayersAreKept`: the name is not empty, has no NUL, is not a namespace
alone, is no overlay name and is not the label, so it is plain (`plain_iff`). -/
theorem the_names_of_layers_are_kept : TheNamesOfLayersAreKept := by
  intro attr ns rest member is_it nonempty no_nul not_overlay not_label
  refine WP.spec_mono (class_answers attr) ?_
  intro c answers
  refine (plain_iff attr.val c answers).mpr ⟨?_, ?_, ?_, ?_, not_label⟩
  · rw [is_it]; intro nil; exact nonempty (List.append_eq_nil_iff.mp nil).2
  · rw [is_it]
    intro has_nul
    rcases List.mem_append.mp has_nul with in_ns | in_rest
    · exact (the_namespaces_are_plain.1 ns member).2 in_ns
    · exact no_nul in_rest
  · rw [is_it]
    intro whole
    have : ns = ns ++ rest :=
      no_namespace_in_another ns member _ whole (List.prefix_append _ _)
    exact nonempty (by simpa using this)
  · rw [is_it]
    rintro ⟨q, qm, begins⟩
    have qb : q <+: ns ++ rest := (List.prefix_append q _).trans begins
    have : ns = q := one_namespace_only (ns ++ rest) ns q member qm (List.prefix_append _ _) qb
    subst this
    exact not_overlay ((List.prefix_append_right_inj ns).mp begins)

/-- Proof of `TheNamesOfRealLayersAreKept`: each name is a namespace and a rest that
`TheNamesOfLayersAreKept` asks for; the conditions on the words are computed. -/
theorem the_names_of_real_layers_are_kept : TheNamesOfRealLayersAreKept := by
  rintro attr (is_it | is_it | is_it | is_it | is_it | is_it)
  · exact the_names_of_layers_are_kept attr (Text "security.") (Text "capability")
      (by decide) (by rw [is_it]; decide) (by decide) (by decide) (by decide)
      (by rw [is_it]; decide)
  · exact the_names_of_layers_are_kept attr (Text "security.") (Text "ima")
      (by decide) (by rw [is_it]; decide) (by decide) (by decide) (by decide)
      (by rw [is_it]; decide)
  · exact the_names_of_layers_are_kept attr (Text "system.") (Text "posix_acl_access")
      (by decide) (by rw [is_it]; decide) (by decide) (by decide) (by decide)
      (by rw [is_it]; decide)
  · exact the_names_of_layers_are_kept attr (Text "system.") (Text "posix_acl_default")
      (by decide) (by rw [is_it]; decide) (by decide) (by decide) (by decide)
      (by rw [is_it]; decide)
  · exact the_names_of_layers_are_kept attr (Text "user.") (Text "xdg.origin.url")
      (by decide) (by rw [is_it]; decide) (by decide) (by decide) (by decide)
      (by rw [is_it]; decide)
  · exact the_names_of_layers_are_kept attr (Text "user.") (Text "overlay")
      (by decide) (by rw [is_it]; decide) (by decide) (by decide) (by decide)
      (by rw [is_it]; decide)

/-- Proof of `WhatIsRefusedExactly`: the three statements about refusals are three of the five of
`class_answers`, and a refusal is one of three. -/
theorem what_is_refused_exactly : WhatIsRefusedExactly := by
  intro attr
  refine WP.spec_mono (class_answers attr) ?_
  intro c ⟨empty, nul, no_name, _, _⟩
  refine ⟨⟨?_, ?_⟩, empty, nul, no_name⟩
  · rintro ⟨why, is_it⟩
    cases why
    · exact Or.inl (empty.mp is_it)
    · exact Or.inr (Or.inl (nul.mp is_it).2)
    · exact Or.inr (Or.inr (no_name.mp is_it))
  · rintro (nil | has_nul | member)
    · exact ⟨_, empty.mpr nil⟩
    · by_cases nil : attr.val = []
      · exact ⟨_, empty.mpr nil⟩
      · exact ⟨_, nul.mpr ⟨nil, has_nul⟩⟩
    · exact ⟨_, no_name.mpr member⟩

/-- Proof of `WhatIsOverlayAndWhatIsLabelExactly`: the two statements of `class_answers`, with the
overlay names written as the four words. -/
theorem what_is_overlay_and_what_is_label_exactly : WhatIsOverlayAndWhatIsLabelExactly := by
  intro attr
  refine WP.spec_mono (class_answers attr) ?_
  intro c ⟨_, _, _, overlay, label⟩
  refine ⟨?_, label⟩
  rw [overlay, overlay_name_iff_four]

end OverlayCore
