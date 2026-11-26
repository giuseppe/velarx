-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: facts about lists of bytes that the proof of `normalize` uses, with no
-- Rust in them: a list is what `TrimSlashes` leaves and `/` only (`trim_parts`); a list cut at its
-- first `://` is the three parts put together again (`scheme_split_puts_together`); the Hub under its
-- one name is no longer than the host (`hub_of_is_not_longer`); the first bytes of a list that are not
-- `/` are the beginning of it and the rest begins with a `/` or is empty.
-- Why it is needed: `normalize` cuts the key in places that the scans find, and what it makes of the
-- pieces is read from these facts.
-- Read before this file: Spec.lean.
-- Notation: `l.takeWhile p` and `l.dropWhile p` are what is before and what is from the first
-- element that does not satisfy `p`; `l.take n` and `l.drop n` are the first `n` elements of `l`
-- and `l` without them.
import AuthCore.Spec

open Aeneas Aeneas.Std Result velarx_auth_core

namespace AuthCore

/-- A list is what `TrimSlashes` leaves of it and then only `/`. -/
theorem trim_parts (m : Bytes) : ∃ S, m = TrimSlashes m ++ S ∧ ∀ x ∈ S, x = Slash := by
  refine ⟨(m.reverse.takeWhile (fun b => decide (b = Slash))).reverse, ?_, ?_⟩
  · unfold TrimSlashes
    have := List.takeWhile_append_dropWhile (p := fun b => decide (b = Slash)) (l := m.reverse)
    conv_lhs => rw [← List.reverse_reverse m, ← this]
    rw [List.reverse_append]
  · intro x hx
    rw [List.mem_reverse] at hx
    have := List.all_eq_true.mp List.all_takeWhile x hx
    simpa using this

/-- What `TrimSlashes` leaves of a list is the beginning of it. -/
theorem trim_is_a_beginning (m : Bytes) : TrimSlashes m <+: m := by
  obtain ⟨S, h, _⟩ := trim_parts m
  exact ⟨S, h.symm⟩

/-- What `TrimSlashes` leaves is no longer than the list. -/
theorem trim_is_not_longer (m : Bytes) : (TrimSlashes m).length ≤ m.length :=
  (trim_is_a_beginning m).length_le

/-- A list cut at its first `://` is the scheme, the three bytes and the rest. -/
theorem scheme_split_puts_together (l a b : Bytes) (h : SchemeSplit l = some (a, b)) :
    l = a ++ SchemeEnd ++ b := by
  induction l generalizing a b with
  | nil => simp [SchemeSplit] at h
  | cons c l ih =>
    unfold SchemeSplit at h
    by_cases begins : SchemeEnd <+: c :: l
    · simp only [begins, ↓reduceIte, Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      simp only [List.nil_append]
      have eq_take := List.prefix_iff_eq_take.mp begins
      have three : SchemeEnd.length = 3 := rfl
      rw [three] at eq_take
      conv_lhs => rw [← List.take_append_drop 3 (c :: l)]
      rw [← eq_take]
    · simp only [begins, ↓reduceIte] at h
      cases hs : SchemeSplit l with
      | none => simp [hs] at h
      | some p =>
        simp only [hs, Option.map_some, Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, rfl⟩ := h
        have := ih p.1 p.2 hs
        simp [this]

/-- The Hub under its one name is no longer than the host. -/
theorem hub_of_is_not_longer (h : Bytes) : (HubOf h).length ≤ h.length := by
  unfold HubOf
  split
  · rename_i hub
    rcases hub with rfl | rfl <;> decide
  · exact le_refl _

end AuthCore
