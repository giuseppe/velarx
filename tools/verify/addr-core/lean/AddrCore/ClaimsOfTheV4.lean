-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the claims of Spec.lean about the function in general and about IPv4
--   (`WhatIsLocalExactly`, `ThePublicV4Addresses`, `TheTableAsNumbers`, `TheFunctionsAlwaysReturn`).
-- Why it is needed: each is `local_v4_is` or `local_v6_is` read as the claim says.
-- Read before this file: Spec.lean, TheV4.lean, TheV6.lean.
-- Notation: `WP.spec_mono` weakens what a function's answer satisfies: if the answer satisfies `P` and `P`
--   gives `Q` then it satisfies `Q`.
import AddrCore.TheForms
open Aeneas Aeneas.Std Result velarx_addr_core
namespace AddrCore

/-- Proof of `WhatIsLocalExactly`: it is `local_v4_is` and `local_v6_is`. -/
theorem what_is_local_exactly : WhatIsLocalExactly := by
  refine ⟨fun a => ?_, fun a => ?_⟩
  · exact WP.spec_mono (local_v4_is a) (fun _ same => same)
  · exact WP.spec_mono (local_v6_is a) (fun _ same => same)

/-- Proof of `TheFunctionsAlwaysReturn`: `local_v4_is` and `local_v6_is` say that the functions return. -/
theorem the_functions_always_return : TheFunctionsAlwaysReturn :=
  ⟨fun a => WP.spec_mono (local_v4_is a) (fun _ _ => trivial),
   fun a => WP.spec_mono (local_v6_is a) (fun _ _ => trivial)⟩

/-- Proof of `ThePublicV4Addresses`: public is the answer `false`, which by `local_v4_is` is: in no prefix. -/
theorem the_public_v4_addresses : ThePublicV4Addresses := by
  intro a
  refine WP.spec_mono (local_v4_is a) ?_
  intro r same
  cases r
  · simp only [Bool.false_eq_true, false_iff, IsLocalV4, not_exists, not_and] at same
    exact ⟨fun _ q q_in => same q q_in, fun _ => rfl⟩
  · have found := same.mp rfl
    obtain ⟨q, q_in, in_q⟩ := found
    exact ⟨fun no => Bool.noConfusion no, fun none => absurd in_q (none q q_in)⟩

/-- Proof of `TheTableAsNumbers`: the numbers are computed. -/
theorem the_table_as_numbers : TheTableAsNumbers := by
  unfold TheTableAsNumbers LocalV4 Ipv4
  decide +kernel

end AddrCore
