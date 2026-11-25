-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `class` answers for any name, as five statements (`ClassIs`): it is
-- `Refused Empty`, `Refused Nul`, `Refused NoName`, `Overlay` or `Label` exactly when ... (the
-- claims of Spec.lean are read off these).
-- Why it is needed: `class` is a chain of tests (empty, NUL, a namespace alone, an overlay name,
-- the label); one proof of the whole chain gives every claim about names.
-- Read before this file: Spec.lean, TheByteChecks.lean.
-- Notation: `f x ⦃ r => P r ⦄` reads: the Rust function `f`, given `x`, returns and its answer `r`
-- satisfies `P r`.  `a <+: b` says the list `a` is the beginning of `b`; `decide` computes a
-- statement about fixed lists.
import OverlayCore.TheByteChecks
open Aeneas Aeneas.Std Result velarx_overlay_core
namespace OverlayCore

/-- No namespace begins another one. -/
theorem no_namespace_in_another : ∀ p ∈ Namespaces, ∀ q ∈ Namespaces, p <+: q → p = q := by
  decide

/-- No namespace is the beginning of another: a name begins with at most one of them. -/
theorem one_namespace_only (bs p q : List Std.U8) (pm : p ∈ Namespaces) (qm : q ∈ Namespaces)
    (pb : p <+: bs) (qb : q <+: bs) : p = q := by
  rcases Nat.le_total p.length q.length with short | short
  · exact no_namespace_in_another p pm q qm (List.prefix_of_prefix_length_le pb qb short)
  · exact (no_namespace_in_another q qm p pm (List.prefix_of_prefix_length_le qb pb short)).symm

/-- Facts about fixed words, by computation: no namespace is empty or has a NUL; the empty name
is no namespace and no overlay name and not the label; the label has no NUL. -/
theorem the_namespaces_are_plain :
    (∀ p ∈ Namespaces, p ≠ [] ∧ 0#u8 ∉ p) ∧ [] ∉ Namespaces ∧ ¬ OverlayName [] ∧
    [] ≠ Text "security.selinux" ∧ 0#u8 ∉ Text "security.selinux" := by
  have nonempty : ∀ p ∈ Namespaces, p ≠ [] := by decide
  refine ⟨by decide, by decide, ?_, by decide, by decide⟩
  rintro ⟨p, member, begins⟩
  have short := begins.length_le
  have long := List.length_pos_of_ne_nil (nonempty p member)
  simp only [List.length_append, List.length_nil] at short
  omega

/-- What `namespace` answers: its length when the name begins with one, else 0. -/
def NamespaceLength (bs : List Std.U8) (ns : Nat) : Prop :=
  (ns = 0 ∧ ∀ p ∈ Namespaces, ¬ p <+: bs) ∨ ∃ p ∈ Namespaces, p <+: bs ∧ ns = p.length

/-- A name is a namespace exactly when it is as long as the namespace it begins with, and that
is not 0. -/
theorem is_a_namespace_iff (bs : List Std.U8) (ns : Nat) (found : NamespaceLength bs ns) :
    bs ∈ Namespaces ↔ 0 < ns ∧ ns = bs.length := by
  have nonempty : ∀ p ∈ Namespaces, p ≠ [] := (the_namespaces_are_plain.1 · · |>.1)
  constructor
  · intro member
    rcases found with ⟨_, none⟩ | ⟨p, pm, begins, same⟩
    · exact absurd (List.prefix_refl bs) (none bs member)
    · have : p = bs := one_namespace_only bs p bs pm member begins (List.prefix_refl bs)
      subst this
      exact ⟨by have := List.length_pos_of_ne_nil (nonempty p pm); omega, same⟩
  · rintro ⟨positive, same⟩
    rcases found with ⟨zero, _⟩ | ⟨p, pm, begins, same_p⟩
    · omega
    · have : p = bs := begins.eq_of_length (by omega)
      rw [← this]; exact pm

/-- A name is an overlay name exactly when it begins with a namespace and what follows begins
with `overlay.`. -/
theorem is_an_overlay_name_iff (bs : List Std.U8) (ns : Nat) (found : NamespaceLength bs ns) :
    OverlayName bs ↔ 0 < ns ∧ (Text "overlay.") <+: bs.drop ns := by
  have nonempty : ∀ p ∈ Namespaces, p ≠ [] := (the_namespaces_are_plain.1 · · |>.1)
  constructor
  · rintro ⟨q, qm, begins⟩
    rcases found with ⟨_, none⟩ | ⟨p, pm, pb, same⟩
    · exact absurd (List.prefix_append q _ |>.trans begins) (none q qm)
    · have qb : q <+: bs := (List.prefix_append q _).trans begins
      have : p = q := one_namespace_only bs p q pm qm pb qb
      subst this
      refine ⟨by have := List.length_pos_of_ne_nil (nonempty p pm); omega, ?_⟩
      obtain ⟨rest, is_rest⟩ := begins
      rw [same, ← is_rest, List.append_assoc, List.drop_left' rfl]
      exact List.prefix_append _ _
  · rintro ⟨positive, begins⟩
    rcases found with ⟨zero, _⟩ | ⟨p, pm, pb, same⟩
    · omega
    · refine ⟨p, pm, ?_⟩
      obtain ⟨rest, is_rest⟩ := pb
      rw [← is_rest]
      rw [same, ← is_rest, List.drop_left' rfl] at begins
      exact (List.prefix_append_right_inj p).mpr begins

/-- The five answers about a class, in one statement. -/
def ClassIs (bs : List Std.U8) (c : Class) : Prop :=
  (c = Class.Refused Refusal.Empty ↔ bs = []) ∧
  (c = Class.Refused Refusal.Nul ↔ bs ≠ [] ∧ 0#u8 ∈ bs) ∧
  (c = Class.Refused Refusal.NoName ↔ bs ∈ Namespaces) ∧
  (c = Class.Overlay ↔ 0#u8 ∉ bs ∧ OverlayName bs) ∧
  (c = Class.Label ↔ bs = Text "security.selinux")

/-- A name that is a namespace is not the SELinux label. -/
theorem selinux_is_no_namespace : Text "security.selinux" ∉ Namespaces := by decide

/-- The SELinux label is no overlay name. -/
theorem selinux_is_no_overlay_name : ¬ OverlayName (Text "security.selinux") := by
  unfold OverlayName; decide

/-- A name of the length of the label that begins with it is the label. -/
theorem label_iff (bytes : Slice Std.U8) (is_label : LABEL.val = Text "security.selinux") :
    (Slice.len bytes = Slice.len LABEL ∧ LABEL.val <+: bytes.val) ↔
      bytes.val = Text "security.selinux" := by
  constructor
  · rintro ⟨same_length, begins⟩
    have : bytes.val.length = LABEL.val.length := by
      have := congrArg Std.UScalar.val same_length
      simpa [Slice.len_val] using this
    rw [← is_label]
    exact (begins.eq_of_length this.symm).symm
  · intro same
    rw [← is_label] at same
    refine ⟨?_, by rw [same]⟩
    apply Std.UScalar.eq_of_val_eq
    simp [same]

/-- The end of `class`, for a name that is not refused and not an overlay name: it is the label
exactly when it is the label's bytes, and plain otherwise. -/
theorem label_tail (bytes : Slice Std.U8) (is_label : LABEL.val = Text "security.selinux")
    (nonempty : bytes.val ≠ []) (no_nul : 0#u8 ∉ bytes.val) (not_ns : bytes.val ∉ Namespaces)
    (not_overlay : ¬ OverlayName bytes.val) :
    (if Slice.len bytes = Slice.len LABEL then
      do
      let b3 ← has_at bytes 0#usize LABEL
      if b3 then ok Class.Label else ok Class.Plain
     else ok Class.Plain) ⦃ c => ClassIs bytes.val c ⦄ := by
  have lab := label_iff bytes is_label
  by_cases same : Slice.len bytes = Slice.len LABEL
  · simp only [same, ite_true]
    step as ⟨ b3, is_b3 ⟩
    by_cases begins : b3 = true
    · simp only [begins, ite_true]
      refine (WP.spec_ok _).mpr ?_
      have is_it := lab.mp ⟨same, is_b3.mp begins⟩
      simpa [ClassIs, nonempty, no_nul, not_ns, not_overlay] using is_it
    · simp only [begins, Bool.false_eq_true, ite_false]
      refine (WP.spec_ok _).mpr ?_
      have not_it : bytes.val ≠ Text "security.selinux" := fun is_it =>
        begins (is_b3.mpr (lab.mpr is_it).2)
      simp [ClassIs, nonempty, no_nul, not_ns, not_overlay, not_it]
  · simp only [same, ite_false]
    refine (WP.spec_ok _).mpr ?_
    have not_it : bytes.val ≠ Text "security.selinux" := fun is_it => same (lab.mpr is_it).1
    simp [ClassIs, nonempty, no_nul, not_ns, not_overlay, not_it]

/-- **What `class` answers**, for every name: the five statements of `ClassIs`.  From the Rust
function in the order of its tests: `namespace` is called, then an empty name is refused, then a
name with a NUL, then a namespace alone, then a name that is a namespace and `overlay.` is the
overlay's, and the end tells the label from the rest (`label_tail`). -/
theorem class_answers (bytes : Slice Std.U8) :
    «class» bytes ⦃ c => ClassIs bytes.val c ⦄ := by
  obtain ⟨_, _, _, _, is_overlay, is_label⟩ := the_words_are_the_text
  obtain ⟨_, empty_is_nothing, empty_is_no_overlay, empty_is_not_label, label_has_no_nul⟩ :=
    the_namespaces_are_plain
  have len_eq : bytes.length = bytes.val.length := rfl
  unfold «class»
  -- the length of the namespace the name begins with, and what it means for the tests below
  step with namespace_answers as ⟨ ns, found ⟩
  have is_ns := is_a_namespace_iff bytes.val ns.val found
  have is_ov := is_an_overlay_name_iff bytes.val ns.val found
  -- the empty name is refused
  step as ⟨ empty, is_empty ⟩
  by_cases e : empty = true
  · simp only [e, ite_true]
    refine (WP.spec_ok _).mpr ?_
    have nil : bytes.val = [] := by
      rw [is_empty] at e; simpa [Slice.length] using e
    simp only [ClassIs, nil]
    simp [empty_is_nothing, empty_is_no_overlay, empty_is_not_label]
  simp only [e, Bool.false_eq_true, ite_false]
  have nonempty : bytes.val ≠ [] := by
    intro nil; apply e; rw [is_empty]; simp [Slice.length, nil]
  -- a name with a NUL is refused
  step as ⟨ nul, is_nul ⟩
  by_cases n : nul = true
  · simp only [n, ite_true]
    refine (WP.spec_ok _).mpr ?_
    have has_nul : 0#u8 ∈ bytes.val := is_nul.mp n
    have not_ns : bytes.val ∉ Namespaces := fun m =>
      (the_namespaces_are_plain.1 _ m).2 has_nul
    have not_label : bytes.val ≠ Text "security.selinux" := fun same =>
      label_has_no_nul (same ▸ has_nul)
    simp [ClassIs, nonempty, has_nul, not_ns, not_label]
  simp only [n, Bool.false_eq_true, ite_false]
  have no_nul : 0#u8 ∉ bytes.val := fun m => n (is_nul.mpr m)
  -- a namespace alone (the name is as long as the namespace) is refused
  by_cases whole : ns = Slice.len bytes
  · simp only [whole, ite_true]
    refine (WP.spec_ok _).mpr ?_
    have positive : 0 < bytes.val.length := List.length_pos_of_ne_nil nonempty
    have member : bytes.val ∈ Namespaces :=
      is_ns.mpr ⟨by rw [whole]; simp; exact positive,
        by rw [whole]; simp⟩
    have not_overlay : ¬ OverlayName bytes.val := by
      intro overlay
      obtain ⟨_, begins⟩ := is_ov.mp overlay
      have same : ns.val = bytes.val.length := by rw [whole]; simp
      rw [same, List.drop_length] at begins
      have := begins.length_le
      simp [Text] at this
    have not_label : bytes.val ≠ Text "security.selinux" := fun same =>
      selinux_is_no_namespace (same ▸ member)
    simp [ClassIs, nonempty, no_nul, member, not_overlay, not_label]
  simp only [whole, ite_false]
  have not_ns : bytes.val ∉ Namespaces := fun m => whole (by
    obtain ⟨_, same⟩ := is_ns.mp m
    exact Std.UScalar.eq_of_val_eq (by simpa [Slice.len_val] using same))
  -- what follows the namespace is `overlay.` or it is not
  step with has_at_answers as ⟨ b2, is_b2 ⟩
  have is_b2' : b2 = true ↔ Text "overlay." <+: bytes.val.drop ns.val := by
    rw [is_b2, is_overlay]
    refine ⟨fun h => h.2, fun begins => ⟨?_, begins⟩⟩
    have short := begins.length_le
    have text_length : (Text "overlay.").length = 8 := by decide
    have word_length : OVERLAY.length = 8 := by
      show OVERLAY.val.length = 8
      rw [is_overlay, text_length]
    simp only [List.length_drop] at short
    have := List.length_pos_of_ne_nil nonempty
    omega
  by_cases b : b2 = true
  · simp only [b, ite_true]
    by_cases positive : ns > 0#usize
    · simp only [positive, ite_true]
      refine (WP.spec_ok _).mpr ?_
      have overlay : OverlayName bytes.val := is_ov.mpr ⟨by scalar_tac, is_b2'.mp b⟩
      have not_label : bytes.val ≠ Text "security.selinux" := fun same =>
        selinux_is_no_overlay_name (same ▸ overlay)
      simp [ClassIs, nonempty, no_nul, not_ns, overlay, not_label]
    · simp only [positive, ite_false]
      exact label_tail bytes is_label nonempty no_nul not_ns (fun overlay => positive (by
        have := (is_ov.mp overlay).1; scalar_tac))
  · simp only [b, Bool.false_eq_true, ite_false]
    exact label_tail bytes is_label nonempty no_nul not_ns (fun overlay => b
      (is_b2'.mpr (is_ov.mp overlay).2))

end OverlayCore
