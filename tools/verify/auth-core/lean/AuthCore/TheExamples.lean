-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the worked examples of Spec.lean: a few keys and hosts, the Hub under its one
-- name, a key in capitals, a path by whole components, and `s3://` that keeps its `://`.
-- Why it is needed: they show what the definitions of Spec.lean say on keys a reader knows.
-- Read before this file: Spec.lean.
-- Notation: `decide` checks a statement by computing it.
import AuthCore.Spec

namespace AuthCore

open Aeneas Aeneas.Std

/-- **`WorkedExamples`**. -/
theorem worked_examples : WorkedExamples := by
  unfold WorkedExamples
  have a_plain : HubOf [97#u8] = [97#u8] := by unfold HubOf; simp only [show ¬ ([97#u8] = HubIndex ∨ [97#u8] = HubRegistry) by decide, ↓reduceIte]
  have ab_plain : HubOf [97#u8, 98#u8] = [97#u8, 98#u8] := by unfold HubOf; simp only [show ¬ ([97#u8, 98#u8] = HubIndex ∨ [97#u8, 98#u8] = HubRegistry) by decide, ↓reduceIte]
  refine ⟨by decide, by decide, by decide, ?_, ?_, ?_, ?_, ?_, ?_, ?_, by decide, by decide, by decide,
    by decide⟩
  · exact Or.inl a_plain.symm
  · simp [Matches, ab_plain]
  · simp [Matches, a_plain]
  · exact Or.inr ⟨[110#u8], by rw [a_plain]; rfl, by simp, Or.inr ⟨[120#u8], by simp⟩⟩
  · simp [Matches, a_plain, Slash]
  · simp [Matches, a_plain]
  · exact Or.inl (by simp [HubOf, HubIndex, HubName])

end AuthCore
