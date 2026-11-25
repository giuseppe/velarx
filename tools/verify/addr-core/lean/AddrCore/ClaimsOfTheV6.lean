-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the claims of Spec.lean about the IPv6 addresses and the forms that
--   carry an IPv4 address (`ThePublicV6Addresses`, `TheEmbeddedAddressesAreJudgedAsTheirV4`,
--   `NoFormOfALocalV4IsPublic`).
-- Why it is needed: rule 4 of lib.rs, an address that embeds an IPv4 one is local exactly when it is, for
--   both functions together.
-- Read before this file: Spec.lean, TheForms.lean, ClaimsOfTheV4.lean.
-- Notation: `step as ⟨ r, hr ⟩` runs a function and names its answer `r` and what is known of it `hr`.
import AddrCore.ClaimsOfTheV4
open Aeneas Aeneas.Std Result velarx_addr_core
namespace AddrCore

/-- Proof of `ThePublicV6Addresses`: the answer `false` is, by `local_v6_is`, in no prefix of `LocalV6` and in no form with a local IPv4 address. -/
theorem the_public_v6_addresses : ThePublicV6Addresses := by
  intro a
  refine WP.spec_mono (local_v6_is a) ?_
  intro r same
  cases r
  · simp only [Bool.false_eq_true, false_iff, IsLocalV6, not_or, not_exists, not_and] at same
    exact ⟨fun _ => ⟨fun q q_in => same.1 q q_in, fun e e_in in_e => same.2 e e_in in_e⟩, fun _ => rfl⟩
  · have found := same.mp rfl
    refine ⟨fun no => Bool.noConfusion no, fun ⟨outside, public_inside⟩ => absurd found ?_⟩
    rintro (⟨q, q_in, in_q⟩ | ⟨e, e_in, in_e, local_v4⟩)
    · exact outside q q_in in_q
    · exact public_inside e e_in in_e local_v4

/-- the IPv6 address of the 16 bytes `a` and the IPv4 address `b` in it, as the claims say it -/
theorem form_answers (a : Std.Array Std.U8 16#usize) (b : Std.Array Std.U8 4#usize)
    (e : Nat × Nat × Nat) (e_in : e ∈ Embedded) (embeds : EmbedsIn a.val b.val e) :
    local_v4 b ⦃ s => local_v6 a ⦃ r => (r = true ↔ s = true) ⦄ ⦄ := by
  obtain ⟨in_e, bytes⟩ := embeds
  have length : a.val.length = 16 := by simp
  step as ⟨ s, same_v4 ⟩
  step as ⟨ r, same_v6 ⟩
  rw [same_v6, same_v4, v6_in_form _ e e_in in_e, embedded_v4_is_its_bytes a.val length e e_in, ← bytes]

/-- Proof of `TheEmbeddedAddressesAreJudgedAsTheirV4`: from `form_answers`, two answers that are `true` together are equal. -/
theorem the_embedded_addresses_are_judged_as_their_v4 : TheEmbeddedAddressesAreJudgedAsTheirV4 := by
  intro a b e e_in embeds
  refine WP.spec_mono (form_answers a b e e_in embeds) ?_
  intro s ok
  refine WP.spec_mono ok ?_
  intro r same
  cases r <;> cases s <;> simp_all

/-- Proof of `NoFormOfALocalV4IsPublic`: from `form_answers`. -/
theorem no_form_of_a_local_v4_is_public : NoFormOfALocalV4IsPublic := by
  intro a b e e_in embeds
  refine WP.spec_mono (form_answers a b e e_in embeds) ?_
  intro s ok local_s
  refine WP.spec_mono ok ?_
  intro r same
  exact same.mpr local_s

end AddrCore
