-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `hub_alias` and `registry` answer: `hub_alias host` is `true` exactly
-- for `index.docker.io` and `registry-1.docker.io`, and `registry host` is `HubOf host`, the host
-- with the three names of the Hub made one.
-- Why it is needed: `matches`, `exact` and `normalize` read the host through `registry`.
-- Read before this file: Spec.lean, Bytes.lean.
-- Notation: `step as ⟨ x, hx ⟩` runs one line of a Rust function and names its result `x` and what
-- is known of it `hx`.
import AuthCore.Spec
import AuthCore.Bytes

open Aeneas Aeneas.Std Result velarx_auth_core

namespace AuthCore

/-- The bytes of a literal slice are the bytes written. -/
theorem literal_bytes (n : Std.Usize) (l : List Std.U8) (h : l.length = n.val) :
    (Array.to_slice (Array.make n l h)).val = l := by
  simp [Array.to_slice, Array.make]

/-- `docker.io` as the crate has it is the bytes of `HubName`. -/
theorem hub_is_the_name : HUB.val = HubName := by
  unfold HUB
  rw [literal_bytes]
  rfl

/-- **`hub_alias`** answers `true` exactly for `index.docker.io` and `registry-1.docker.io`. -/
@[step] theorem hub_alias_is_the_two_names (host : Slice Std.U8) :
    hub_alias host ⦃ r => r = true ↔ (host.val = HubIndex ∨ host.val = HubRegistry) ⦄ := by
  unfold hub_alias
  simp only [lift, Std.bind_ok]
  step as ⟨ b, is_b ⟩
  by_cases first : b = true
  · simp only [first, ite_true]
    refine (WP.spec_ok _).mpr ?_
    have : host.val = HubIndex := by
      have := is_b.mp first
      rw [this]
      rfl
    simp [this]
  · simp only [first, Bool.false_eq_true, ite_false]
    step as ⟨ c, is_c ⟩
    have not_first : host.val ≠ HubIndex := by
      intro h
      exact first (is_b.mpr (by rw [h]; rfl))
    simp only [is_c, literal_bytes]
    simp [not_first, HubRegistry]

/-- **`registry`** is `HubOf` of the host: `docker.io` for the three names of the Hub, the host
itself for any other. -/
@[step] theorem registry_is_the_hub_of_the_host (host : Slice Std.U8) :
    registry host ⦃ r => r.val = HubOf host.val ⦄ := by
  unfold registry
  step as ⟨ b, is_b ⟩
  by_cases is_alias : b = true
  · simp only [is_alias, ite_true]
    refine (WP.spec_ok _).mpr ?_
    simp [HubOf, (is_b.mp is_alias), hub_is_the_name]
  · simp only [is_alias]
    refine (WP.spec_ok _).mpr ?_
    have : ¬ (host.val = HubIndex ∨ host.val = HubRegistry) := fun h => is_alias (is_b.mpr h)
    simp [HubOf, this]

end AuthCore
