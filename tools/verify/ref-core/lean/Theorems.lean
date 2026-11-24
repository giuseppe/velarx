-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the list of what is proved of crates/ref-core.  The statements are in
-- RefCore/Spec.lean, the proofs in RefCore/Claims.lean (which uses the files before it in
-- RefCore/).
-- ../../run ends on this file: it fails unless every line `#proved T` below prints "proved: T".
--
-- Why it is needed: Lean checks a proof when it is read, but nothing says that the theorem is the
-- one of the statement or that no `sorry` or new axiom is behind it.  `#proved T`
-- (../../Proved.lean) prints the axioms `T` rests on and fails unless they are the three of Lean
-- and the library functions the crate has no model of (there are none: Models.lean is empty).
--
-- Read before this file: RefCore/Spec.lean.
import Proved
import RefCore.Claims
import RefCore.Examples

-- Each theorem is a proof of the statement of that name in Spec.lean: Lean checks the type of each
-- line below, so Theorems.lean and Spec.lean suffice.
example : RefCore.ParseAlwaysReturns :=
  RefCore.parse_always_returns
example : RefCore.TheOtherReadersAlwaysReturn :=
  RefCore.the_other_readers_always_return
example : RefCore.AcceptedReferencesAreInTheGrammar :=
  RefCore.accepted_references_are_in_the_grammar
example : RefCore.ParseAcceptsTheGrammar :=
  RefCore.parse_accepts_the_grammar
example : RefCore.AcceptedStringsHaveOneReading :=
  RefCore.accepted_strings_have_one_reading
example : RefCore.NormalNameIsFixed :=
  RefCore.normal_name_is_fixed
example : RefCore.NormalNameIsInTheGrammar :=
  RefCore.normal_name_is_in_the_grammar
example : RefCore.PrintWritesTheNormalName :=
  RefCore.print_writes_the_normal_name
example : RefCore.PrintedNormalNameIsAccepted :=
  RefCore.printed_normal_name_is_accepted
example : RefCore.AcceptedPartsAreSafe :=
  RefCore.accepted_parts_are_safe
example : RefCore.AcceptedBytesAreOnlyThese :=
  RefCore.accepted_bytes_are_only_these
example : RefCore.ExamplesAreRead :=
  RefCore.examples_are_read
example : RefCore.LooksLikeHostIsExact :=
  RefCore.looks_like_host_is_exact
example : RefCore.HostErrorFindsExactlyHosts :=
  RefCore.host_error_finds_exactly_hosts
example : RefCore.PrefixErrorFindsExactlyPrefixes :=
  RefCore.prefix_error_finds_exactly_prefixes
example : RefCore.NormalizeAddsTheDefaults :=
  RefCore.normalize_adds_the_defaults

#proved RefCore.parse_always_returns
#proved RefCore.the_other_readers_always_return
#proved RefCore.accepted_references_are_in_the_grammar
#proved RefCore.parse_accepts_the_grammar
#proved RefCore.accepted_strings_have_one_reading
#proved RefCore.accepted_parts_are_safe
#proved RefCore.accepted_bytes_are_only_these
#proved RefCore.examples_are_read
#proved RefCore.looks_like_host_is_exact
#proved RefCore.host_error_finds_exactly_hosts
#proved RefCore.prefix_error_finds_exactly_prefixes
#proved RefCore.normalize_adds_the_defaults
#proved RefCore.normal_name_is_fixed
#proved RefCore.normal_name_is_in_the_grammar
#proved RefCore.print_writes_the_normal_name
#proved RefCore.printed_normal_name_is_accepted

