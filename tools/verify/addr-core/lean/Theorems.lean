-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the list of what is proved of crates/addr-core.  The statements are in
-- AddrCore/Spec.lean, the proofs in the other files of AddrCore/ (the ones named Claims..., which use
-- the files before them).
-- ../../run ends on this file: it fails unless every line `#proved T` below prints "proved: T".
--
-- Why it is needed: Lean checks a proof when it is read, but nothing says that the theorem is the
-- one of the statement or that no `sorry` or new axiom is behind it.  `#proved T`
-- (../../Proved.lean) prints the axioms `T` rests on and fails unless they are the three of Lean
-- and the library functions the crate has no model of (the run prints none for this crate).
--
-- Read before this file: AddrCore/Spec.lean.
import Proved
import AddrCore.ClaimsOfExamples

-- Each theorem is a proof of the statement of that name in Spec.lean: Lean checks the type of each
-- line below, so Theorems.lean and Spec.lean suffice.
example : AddrCore.TheFunctionsAlwaysReturn :=
  AddrCore.the_functions_always_return
#proved AddrCore.the_functions_always_return
example : AddrCore.WhatIsLocalExactly :=
  AddrCore.what_is_local_exactly
#proved AddrCore.what_is_local_exactly
example : AddrCore.ThePublicV4Addresses :=
  AddrCore.the_public_v4_addresses
#proved AddrCore.the_public_v4_addresses
example : AddrCore.TheTableAsNumbers :=
  AddrCore.the_table_as_numbers
#proved AddrCore.the_table_as_numbers
example : AddrCore.TheNamedV4ClassesAreLocal :=
  AddrCore.the_named_v4_classes_are_local
#proved AddrCore.the_named_v4_classes_are_local
example : AddrCore.TheMetadataAddressesAreLocal :=
  AddrCore.the_metadata_addresses_are_local
#proved AddrCore.the_metadata_addresses_are_local
example : AddrCore.ThePublicV4Examples :=
  AddrCore.the_public_v4_examples
#proved AddrCore.the_public_v4_examples
example : AddrCore.ThePublicV6Addresses :=
  AddrCore.the_public_v6_addresses
#proved AddrCore.the_public_v6_addresses
example : AddrCore.TheEmbeddedAddressesAreJudgedAsTheirV4 :=
  AddrCore.the_embedded_addresses_are_judged_as_their_v4
#proved AddrCore.the_embedded_addresses_are_judged_as_their_v4
example : AddrCore.NoFormOfALocalV4IsPublic :=
  AddrCore.no_form_of_a_local_v4_is_public
#proved AddrCore.no_form_of_a_local_v4_is_public
example : AddrCore.TheNamedV6ClassesAreLocal :=
  AddrCore.the_named_v6_classes_are_local
#proved AddrCore.the_named_v6_classes_are_local
example : AddrCore.TheV6Examples :=
  AddrCore.the_v6_examples
#proved AddrCore.the_v6_examples
