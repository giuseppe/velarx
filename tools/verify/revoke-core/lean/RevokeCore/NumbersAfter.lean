-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: which numbers are held of an issuer after the adoption (`StateAfter`): the
-- numbers held before, when no part of the issuer is adopted, and the number of the part that is
-- adopted, when one is.
-- Why it is needed: the claims about what is held afterwards are about the highest of these
-- numbers.
-- Read before this file: Spec.lean.
-- Notation: `List.mem_filterMap`, `List.mem_map` and `List.mem_filter` say what it is to be in a
-- list made by `filterMap`, `map` and `filter`; `∃ i ∈ l, P i` reads "some `i` of `l` has `P`".
import RevokeCore.Spec

open Aeneas Aeneas.Std Result velarx_revoke_core

open Classical

namespace RevokeCore

/-- A number is held of `issuer` after the adoption of the parts at the places `places` exactly
when it was held before and none of the parts adopted is of that issuer (they replace what was
held), or it is the number of a part adopted of that issuer. -/
theorem number_held_after (held : List Held) (parts : List Part) (places : List Nat)
    (issuer : Std.U64) (x : Nat) :
    x ∈ NumbersHeld (StateAfter held parts places) issuer ↔
      (x ∈ NumbersHeld held issuer ∧
        ∀ i ∈ places, ∀ a, parts[i]? = some a → a.issuer ≠ issuer) ∨
      (∃ i ∈ places, ∃ a, parts[i]? = some a ∧ a.issuer = issuer ∧ a.number.val = x) := by
  simp only [NumbersHeld, StateAfter, HeldOf, List.filter_append, List.map_append,
    List.mem_append, List.mem_map, List.mem_filter, List.mem_filterMap, decide_eq_true_eq]
  constructor
  · rintro (⟨h, ⟨⟨member, replaced⟩, same⟩, is_x⟩ |
      ⟨h, ⟨⟨a, ⟨i, in_places, at_i⟩, is_h⟩, same⟩, is_x⟩)
    · -- held before, and not replaced
      refine Or.inl ⟨⟨h, ⟨member, same⟩, is_x⟩, ?_⟩
      intro i in_places a at_i same_issuer
      exact replaced _ ⟨a, ⟨i, in_places, at_i⟩, rfl⟩ (same_issuer.trans same.symm)
    · -- the number of a part adopted
      subst is_h
      exact Or.inr ⟨i, in_places, a, at_i, same, is_x⟩
  · rintro (⟨⟨h, ⟨member, same⟩, is_x⟩, not_replaced⟩ | ⟨i, in_places, a, at_i, same, is_x⟩)
    · refine Or.inl ⟨h, ⟨⟨member, ?_⟩, same⟩, is_x⟩
      rintro _ ⟨a, ⟨i, in_places, at_i⟩, rfl⟩ same_issuer
      exact not_replaced i in_places a at_i (same_issuer.trans same)
    · exact Or.inr ⟨_, ⟨⟨a, ⟨i, in_places, at_i⟩, rfl⟩, same⟩, is_x⟩

end RevokeCore
