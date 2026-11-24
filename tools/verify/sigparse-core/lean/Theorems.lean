-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the list of what is proved of crates/sigparse-core.  The statements are in
-- SigparseCore/Spec.lean, the proofs in SigparseCore/Claims.lean (which uses the other files of
-- SigparseCore/).
-- ../../run ends on this file: it fails unless every line `#proved T` below prints "proved: T".
--
-- Why it is needed: Lean checks a proof when it is read, but nothing says that the theorem is the
-- one of the statement or that no `sorry` or new axiom is behind it.  `#proved T`
-- (../../Proved.lean) prints the axioms `T` rests on and fails unless they are the three of Lean.
--
-- Read before this file: SigparseCore/Spec.lean.
import Proved
import SigparseCore.Claims

-- Each theorem is a proof of the statement of that name in Spec.lean: Lean checks the type of each
-- line below, so Theorems.lean and Spec.lean suffice.
example : SigparseCore.DerElementAlwaysReturns :=
  SigparseCore.der_element_always_returns
example : SigparseCore.DerElementIsAcceptedExactlyWhenItIsWellFormed :=
  SigparseCore.der_element_is_accepted_exactly_when_it_is_well_formed
example : SigparseCore.AnAcceptedDerElementIsDefiniteAndInside :=
  SigparseCore.an_accepted_der_element_is_definite_and_inside
example : SigparseCore.SequenceItemsAlwaysReturns :=
  SigparseCore.sequence_items_always_returns
example : SigparseCore.AcceptedSequenceItemsFillTheSequence :=
  SigparseCore.accepted_sequence_items_fill_the_sequence
example : SigparseCore.PacketsAlwaysReturn :=
  SigparseCore.packets_always_return
example : SigparseCore.AcceptedPacketsCoverTheInput :=
  SigparseCore.accepted_packets_cover_the_input
example : SigparseCore.AcceptedPacketSpansAreInsideTheInput :=
  SigparseCore.accepted_packet_spans_are_inside_the_input
example : SigparseCore.AcceptedPacketsAreNoMoreThanTheLimit :=
  SigparseCore.accepted_packets_are_no_more_than_the_limit
example : SigparseCore.EmptyDataIsAccepted :=
  SigparseCore.empty_data_is_accepted
example : SigparseCore.SignatureAlwaysReturns :=
  SigparseCore.signature_always_returns
example : SigparseCore.AcceptedSignatureIsLaidOutLikeVersion4 :=
  SigparseCore.accepted_signature_is_laid_out_like_version_4
example : SigparseCore.TheTrailerIsTheBytesUpToTheEndOfTheHashedArea :=
  SigparseCore.the_trailer_is_the_bytes_up_to_the_end_of_the_hashed_area
example : SigparseCore.AcceptedValuesFollowTheAreas :=
  SigparseCore.accepted_values_follow_the_areas
example : SigparseCore.TheHashedAreaIsMadeOfSubpackets :=
  SigparseCore.the_hashed_area_is_made_of_subpackets
example : SigparseCore.NoUnknownCriticalSubpacketInTheHashedArea :=
  SigparseCore.no_unknown_critical_subpacket_in_the_hashed_area
example : SigparseCore.NoCriticalNotationIsAccepted :=
  SigparseCore.no_critical_notation_is_accepted
example : SigparseCore.TimesAndFlagsAreOfTheHashedAreaOnly :=
  SigparseCore.times_and_flags_are_of_the_hashed_area_only
example : SigparseCore.EmbeddedSignaturesAreTheValuesOfTheEmbeddedSubpackets :=
  SigparseCore.embedded_signatures_are_the_values_of_the_embedded_subpackets
example : SigparseCore.TheIssuerFingerprintIsInsideTheAreas :=
  SigparseCore.the_issuer_fingerprint_is_inside_the_areas
example : SigparseCore.WellFormedSignaturesAreAccepted :=
  SigparseCore.well_formed_signatures_are_accepted
example : SigparseCore.AcceptedSignaturesAreWellFormed :=
  SigparseCore.accepted_signatures_are_well_formed
example : SigparseCore.SignaturesThatAgreeUpToTheHashedAreaHaveTheSameTimes :=
  SigparseCore.signatures_that_agree_up_to_the_hashed_area_have_the_same_times
example : SigparseCore.ASignatureWithNoSubpacketsIsAccepted :=
  SigparseCore.a_signature_with_no_subpackets_is_accepted
example : SigparseCore.ASignatureWithOneCreationTimeIsAccepted :=
  SigparseCore.a_signature_with_one_creation_time_is_accepted
example : SigparseCore.SimplePacketsAreAccepted :=
  SigparseCore.simple_packets_are_accepted

#proved SigparseCore.der_element_always_returns
#proved SigparseCore.der_element_is_accepted_exactly_when_it_is_well_formed
#proved SigparseCore.an_accepted_der_element_is_definite_and_inside
#proved SigparseCore.sequence_items_always_returns
#proved SigparseCore.accepted_sequence_items_fill_the_sequence
#proved SigparseCore.packets_always_return
#proved SigparseCore.accepted_packets_cover_the_input
#proved SigparseCore.accepted_packet_spans_are_inside_the_input
#proved SigparseCore.accepted_packets_are_no_more_than_the_limit
#proved SigparseCore.empty_data_is_accepted
#proved SigparseCore.signature_always_returns
#proved SigparseCore.accepted_signature_is_laid_out_like_version_4
#proved SigparseCore.the_trailer_is_the_bytes_up_to_the_end_of_the_hashed_area
#proved SigparseCore.accepted_values_follow_the_areas
#proved SigparseCore.the_hashed_area_is_made_of_subpackets
#proved SigparseCore.no_unknown_critical_subpacket_in_the_hashed_area
#proved SigparseCore.no_critical_notation_is_accepted
#proved SigparseCore.times_and_flags_are_of_the_hashed_area_only
#proved SigparseCore.embedded_signatures_are_the_values_of_the_embedded_subpackets
#proved SigparseCore.the_issuer_fingerprint_is_inside_the_areas
#proved SigparseCore.well_formed_signatures_are_accepted
#proved SigparseCore.a_signature_with_no_subpackets_is_accepted
#proved SigparseCore.a_signature_with_one_creation_time_is_accepted
#proved SigparseCore.simple_packets_are_accepted
#proved SigparseCore.accepted_signatures_are_well_formed
#proved SigparseCore.signatures_that_agree_up_to_the_hashed_area_have_the_same_times
