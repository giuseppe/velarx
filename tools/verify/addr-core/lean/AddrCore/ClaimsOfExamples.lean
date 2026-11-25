-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the claims of Spec.lean about worked examples (`ThePublicV4Examples`,
--   `TheV6Examples`): the public DNS servers and the forms of 8.8.8.8 are public, the forms of 127.0.0.1 and
--   of the metadata address are local, the neighbours of every edge.
-- Why it is needed: the examples show that the exact answer of `WhatIsLocalExactly` gives what a reader
--   expects, and that a function that refuses everything does not pass.
-- Read before this file: Spec.lean, ClaimsOfTheNames.lean.
-- Notation: `decide +kernel` has Lean's kernel compute a statement about fixed numbers; `generalize Number
--   a.val = n` forgets that the number is of an address.
import AddrCore.ClaimsOfTheNames
open Aeneas Aeneas.Std Result velarx_addr_core
namespace AddrCore

-- (so that `decide` computes a statement about fixed numbers)
instance (bits n first len : Nat) : Decidable (InPrefix bits n first len) :=
  inferInstanceAs (Decidable (_ ∧ _))

instance (n : Nat) : Decidable (IsLocalV4 n) := inferInstanceAs (Decidable (∃ q ∈ LocalV4, _))

instance (n : Nat) : Decidable (IsLocalV6 n) := inferInstanceAs (Decidable (_ ∨ _))

/-- Proof of `ThePublicV4Examples`: `decide` computes, for the numbers of the list, whether they are in the table (the kernel does the arithmetic). -/
theorem the_public_v4_examples : ThePublicV4Examples := by
  intro a
  refine WP.spec_mono (local_v4_is a) ?_
  intro r same
  constructor
  · intro listed
    have not_local : ¬ IsLocalV4 (Number a.val) := by
      revert listed; generalize Number a.val = n; revert n; decide +kernel
    cases r
    · rfl
    · exact absurd (same.mp rfl) not_local
  · intro listed
    have local_v4 : IsLocalV4 (Number a.val) := by
      revert listed; generalize Number a.val = n; revert n; decide +kernel
    exact same.mpr local_v4

/-- Proof of `TheV6Examples`: `decide` computes, for the numbers of the lists, the answer of `WhatIsLocalExactly`. -/
theorem the_v6_examples : TheV6Examples := by
  intro a
  refine WP.spec_mono (local_v6_is a) ?_
  intro r same
  constructor
  · intro listed
    have local_v6 : IsLocalV6 (Number a.val) := by
      revert listed; generalize Number a.val = n; revert n; decide +kernel
    exact same.mpr local_v6
  · intro listed
    have not_local : ¬ IsLocalV6 (Number a.val) := by
      revert listed; generalize Number a.val = n; revert n; decide +kernel
    cases r
    · rfl
    · exact absurd (same.mp rfl) not_local

end AddrCore
