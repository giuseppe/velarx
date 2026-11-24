-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proof of each claim of Spec.lean, from the theorems of the files of
-- SigparseCore/ that follow the Rust code (BigEndian, Spans, Der, DerSequence, PiecesFrom, Packet,
-- Subpacket, SubpacketLoop, Values, Signature, AreaUnique, Locality).  Each claim of Spec.lean is
-- the weakening of what one of those theorems says of one function (or, for the claims that say
-- what is accepted, a theorem that the function does not refuse), so this file only reads off the
-- part of the theorem the claim is about.
--
-- Why it is needed: Theorems.lean ties each name of Spec.lean to the theorem below, and `#proved`
-- there checks that nothing but Lean's axioms is behind it.
--
-- Read before this file: Spec.lean.
--
-- Notation: `WP.spec_mono h f` is "the function satisfies `P`, and `P` gives `Q`, so it satisfies
-- `Q`" (`f` proves `P → Q`); `fun x hx => ...` is the function that takes `x` and `hx`.
import SigparseCore.Der
import SigparseCore.DerSequence
import SigparseCore.Packet
import SigparseCore.Signature
import SigparseCore.AreaUnique
import SigparseCore.Locality

open Aeneas Aeneas.Std Result velarx_sigparse_core
namespace SigparseCore

/-- `element` always returns. -/
theorem der_element_always_returns : DerElementAlwaysReturns :=
  fun data => WP.spec_mono (element_reads data) (fun _ _ => trivial)

/-- `element` accepts exactly the well-formed elements. -/
theorem der_element_is_accepted_exactly_when_it_is_well_formed :
    DerElementIsAcceptedExactlyWhenItIsWellFormed :=
  fun data => element_reads data

/-- The content of an accepted element is after its header and inside the data. -/
theorem an_accepted_der_element_is_definite_and_inside :
    AnAcceptedDerElementIsDefiniteAndInside := by
  intro data
  refine WP.spec_mono (element_reads data) ?_
  intro r both tag content found
  obtain ⟨_, content_is⟩ := both.1 tag content found
  obtain ⟨after_header, inside⟩ := der_content_is_inside _ _ _ _ _ content_is
  exact ⟨by omega, inside⟩

/-- `sequence_items` always returns. -/
theorem sequence_items_always_returns : SequenceItemsAlwaysReturns :=
  fun data => WP.spec_mono (sequence_items_reads data) (fun _ _ => trivial)

/-- The items of an accepted sequence fill it. -/
theorem accepted_sequence_items_fill_the_sequence : AcceptedSequenceItemsFillTheSequence :=
  fun data => sequence_items_reads data

/-- `packets` always returns. -/
theorem packets_always_return : PacketsAlwaysReturn :=
  fun data => WP.spec_mono (packets_reads data) (fun _ _ => trivial)

/-- The packets of accepted data cover it. -/
theorem accepted_packets_cover_the_input : AcceptedPacketsCoverTheInput :=
  fun data => WP.spec_mono (packets_reads data) (fun _ read packets found => (read packets found).1)

/-- Every piece of an accepted packet lies inside the data. -/
theorem accepted_packet_spans_are_inside_the_input : AcceptedPacketSpansAreInsideTheInput := by
  intro data
  refine WP.spec_mono (packets_reads data) ?_
  intro r read packets found piece member
  exact (pieces_from_inside _ _ _ (read packets found).1).2 piece member |>.2

/-- No more than `MAX_PACKETS` pieces. -/
theorem accepted_packets_are_no_more_than_the_limit : AcceptedPacketsAreNoMoreThanTheLimit := by
  intro data
  refine WP.spec_mono (packets_reads data) ?_
  intro r read packets found
  rw [max_packets_is]
  exact (read packets found).2

/-- The empty data is accepted, with no packet: the loop of `packets` ends at its first turn. -/
theorem empty_data_is_accepted : EmptyDataIsAccepted := by
  unfold EmptyDataIsAccepted packet.packets packet.packets_loop
  rw [loop]
  simp [packet.packets_loop.body, core.option.Option.is_none, Slice.len, Slice.new, Slice.val,
    Data.ListN.ListN.toList, alloc.vec.Vec.new]

/-- `signature` always returns. -/
theorem signature_always_returns : SignatureAlwaysReturns :=
  fun body => WP.spec_mono (signature_reads body) (fun _ _ => trivial)

/-- An accepted signature is laid out like a version 4 packet. -/
theorem accepted_signature_is_laid_out_like_version_4 : AcceptedSignatureIsLaidOutLikeVersion4 := by
  intro body
  refine WP.spec_mono (signature_reads body) ?_
  intro r read signature found
  obtain ⟨version, sig_type, algo, hash, hashed_off, hashed_len, _, unhashed_off, unhashed_len,
    unhashed_fits, _⟩ := read signature found
  exact ⟨version, sig_type, algo, hash, hashed_off, hashed_len, unhashed_off, unhashed_len,
    unhashed_fits⟩

/-- The trailer is the bytes from the start of the body to the end of the hashed area. -/
theorem the_trailer_is_the_bytes_up_to_the_end_of_the_hashed_area :
    TheTrailerIsTheBytesUpToTheEndOfTheHashedArea := by
  intro body
  refine WP.spec_mono (signature_reads body) ?_
  intro r read signature found
  obtain ⟨_, _, _, _, hashed_off, hashed_len, hashed_fits, _⟩ := read signature found
  exact ⟨hashed_off, by omega, hashed_fits⟩

/-- The values follow the areas, and are as many as the algorithm has. -/
theorem accepted_values_follow_the_areas : AcceptedValuesFollowTheAreas := by
  intro body
  refine WP.spec_mono (signature_reads body) ?_
  intro r read signature found
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, values, count, _⟩ := read signature found
  exact ⟨values, count⟩

/-- The hashed area is made of subpackets. -/
theorem the_hashed_area_is_made_of_subpackets : TheHashedAreaIsMadeOfSubpackets := by
  intro body
  refine WP.spec_mono (signature_reads body) ?_
  intro r read signature found
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, hashed_subs, unhashed_subs, hashed_made,
    unhashed_made, _⟩ := read signature found
  exact ⟨hashed_subs, unhashed_subs, hashed_made, unhashed_made⟩

/-- No critical subpacket of an unknown kind is in the hashed area of an accepted signature. -/
theorem no_unknown_critical_subpacket_in_the_hashed_area :
    NoUnknownCriticalSubpacketInTheHashedArea := by
  intro body
  refine WP.spec_mono (signature_reads body) ?_
  intro r read signature found subs made
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, hashed_subs, unhashed_subs, hashed_made,
    _, _, _, _, _, _, criticals, _⟩ := read signature found
  rw [area_made_of_unique _ _ _ _ _ made hashed_made]
  exact criticals

/-- A critical notation is not accepted: the kind 20 is not a known kind. -/
theorem no_critical_notation_is_accepted : NoCriticalNotationIsAccepted := by
  intro body
  refine WP.spec_mono (signature_reads body) ?_
  intro r read signature found subs made sub member is_notation critical
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, hashed_subs, unhashed_subs, hashed_made,
    _, _, _, _, _, _, criticals, _⟩ := read signature found
  rw [area_made_of_unique _ _ _ _ _ made hashed_made] at member
  have known := criticals sub member critical
  rw [is_notation] at known
  simp [KnownKinds, ReadKinds, IgnoredKinds] at known

/-- The times and the key flags are those of the hashed area, and of it only. -/
theorem times_and_flags_are_of_the_hashed_area_only : TimesAndFlagsAreOfTheHashedAreaOnly := by
  intro body
  refine WP.spec_mono (signature_reads body) ?_
  intro r read signature found subs made
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, hashed_subs, unhashed_subs, hashed_made,
    _, created, expires, key_expires, key_flags, four_bytes, _⟩ := read signature found
  rw [area_made_of_unique _ _ _ _ _ made hashed_made]
  exact ⟨created, expires, key_expires, key_flags, four_bytes⟩

/-- The embedded signatures are the values of the embedded subpackets. -/
theorem embedded_signatures_are_the_values_of_the_embedded_subpackets :
    EmbeddedSignaturesAreTheValuesOfTheEmbeddedSubpackets := by
  intro body
  refine WP.spec_mono (signature_reads body) ?_
  intro r read signature found hashed_subs' unhashed_subs' hashed_made' unhashed_made'
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, hashed_subs, unhashed_subs, hashed_made,
    unhashed_made, _, _, _, _, _, _, embedded, _⟩ := read signature found
  rw [area_made_of_unique _ _ _ _ _ hashed_made' hashed_made,
    area_made_of_unique _ _ _ _ _ unhashed_made' unhashed_made]
  exact embedded

/-- The issuer fingerprint lies inside the areas. -/
theorem the_issuer_fingerprint_is_inside_the_areas : TheIssuerFingerprintIsInsideTheAreas := by
  intro body
  refine WP.spec_mono (signature_reads body) ?_
  intro r read signature found
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, hashed_subs, unhashed_subs, hashed_made,
    _, _, _, _, _, _, _, _, fingerprint⟩ := read signature found
  exact fingerprint

/-- A well formed signature packet is accepted. -/
theorem well_formed_signatures_are_accepted : WellFormedSignaturesAreAccepted :=
  fun body good => signature_accepts body good

/-- A byte that is not 0 is there: the list has it at that position. -/
theorem byte_at_is_a_byte (bytes : List Std.U8) (p value : Nat) (read : ByteAt bytes p = value)
    (positive : 0 < value) : ∃ byte, bytes[p]? = some byte ∧ byte.val = value := by
  unfold ByteAt at read
  cases found : bytes[p]? with
  | none => simp [found] at read; omega
  | some byte => simp [found] at read; exact ⟨byte, rfl, read⟩

/-- A signature with no subpacket is accepted. -/
theorem a_signature_with_no_subpackets_is_accepted : ASignatureWithNoSubpacketsIsAccepted := by
  intro body version no_hashed no_unhashed long values
  have hashed_end : HashedEnd body.val = 6 := by simp [HashedEnd, no_hashed]
  have unhashed_end : UnhashedEnd body.val = 8 := by
    simp [UnhashedEnd, hashed_end, no_unhashed]
  have empty_hashed : AreaMadeOf body.val 6 6 [] := rfl
  have empty_unhashed : AreaMadeOf body.val 8 8 [] := rfl
  have good : WellFormedSignature body.val :=
    { version_four := version
      hashed_area_inside := by omega
      hashed_area_is_subpackets := ⟨[], by rw [hashed_end]; exact empty_hashed, by simp⟩
      unhashed_area_inside := by omega
      unhashed_area_is_subpackets := ⟨[], by rw [hashed_end, unhashed_end]; exact empty_unhashed⟩
      values_are_there := by rw [unhashed_end]; exact values }
  refine WP.spec_mono (WP.spec_and (signature_accepts body good) (signature_reads body)) ?_
  rintro r ⟨⟨signature, accepted⟩, read⟩
  obtain ⟨_, _, _, _, hashed_off, hashed_len, _, _, _, _, _, _, _, _, hashed_subs, unhashed_subs,
    hashed_made, _, created, expires, key_expires, key_flags, _⟩ := read signature accepted
  rw [hashed_off, hashed_len, no_hashed] at hashed_made
  have no_subpackets : hashed_subs = [] := area_made_of_unique _ _ _ _ _ hashed_made empty_hashed
  subst no_subpackets
  simp only [LastOfKind, List.filter_nil, List.getLast?_nil, Option.map_none,
    Option.map_eq_none_iff] at created expires key_expires key_flags
  exact ⟨signature, accepted, by omega, created, expires, key_expires, key_flags⟩

/-- A signature with one creation time is accepted, with that time. -/
theorem a_signature_with_one_creation_time_is_accepted :
    ASignatureWithOneCreationTimeIsAccepted := by
  intro body version hashed_six five two no_unhashed long values
  have hashed_end : HashedEnd body.val = 12 := by simp [HashedEnd, hashed_six]
  have unhashed_end : UnhashedEnd body.val = 14 := by
    simp [UnhashedEnd, hashed_end, no_unhashed]
  obtain ⟨length_byte, length_is, length_value⟩ := byte_at_is_a_byte _ _ _ five (by omega)
  let time : Sub := ⟨6, 7, 5⟩
  have time_kind : time.kind body.val = 2 := by simp [time, Sub.kind, two]
  have one_time : AreaMadeOf body.val 6 12 [time] := by
    refine ⟨by omega, rfl, ⟨1, ?_, rfl⟩, by decide, by decide, rfl⟩
    rw [length_at_one_octet body.val 6 12 length_byte length_is (by omega)]
    simp [time, length_value]
  have empty_unhashed : AreaMadeOf body.val 14 14 [] := rfl
  have good : WellFormedSignature body.val :=
    { version_four := version
      hashed_area_inside := by omega
      hashed_area_is_subpackets := by
        refine ⟨[time], by rw [hashed_end]; exact one_time, ?_⟩
        intro sub member
        rw [List.mem_singleton] at member
        subst member
        refine ⟨fun _ => rfl, fun critical => ?_⟩
        simp only [Sub.Critical, time] at critical
        omega
      unhashed_area_inside := by omega
      unhashed_area_is_subpackets := ⟨[], by rw [hashed_end, unhashed_end]; exact empty_unhashed⟩
      values_are_there := by rw [unhashed_end]; exact values }
  refine WP.spec_mono (WP.spec_and (signature_accepts body good) (signature_reads body)) ?_
  rintro r ⟨⟨signature, accepted⟩, read⟩
  obtain ⟨_, _, _, _, hashed_off, hashed_len, _, _, _, _, _, _, _, _, hashed_subs, unhashed_subs,
    hashed_made, _, created, expires, key_expires, key_flags, _⟩ := read signature accepted
  rw [hashed_off, hashed_len, hashed_six] at hashed_made
  have only_time : hashed_subs = [time] := area_made_of_unique _ _ _ _ _ hashed_made one_time
  subst only_time
  have last_created : LastOfKind body.val [time] 2 = some time := by simp [LastOfKind, time_kind]
  have no_other (kind : Nat) (other : kind ≠ 2) : LastOfKind body.val [time] kind = none := by
    simp [LastOfKind, time_kind, other.symm]
  rw [last_created] at created
  rw [no_other 3 (by omega)] at expires
  rw [no_other 9 (by omega)] at key_expires
  rw [no_other 27 (by omega)] at key_flags
  simp only [Option.map_none, Option.map_eq_none_iff] at expires key_expires key_flags
  exact ⟨signature, accepted, by omega, by rw [created]; simp [Sub.Time, time], expires,
    key_expires, key_flags⟩

/-- Packets in the new format with one-byte lengths are accepted. -/
theorem simple_packets_are_accepted : SimplePacketsAreAccepted := by
  intro data parts simple few
  unfold packet.packets
  have max_is := max_packets_is
  have loop_accepts := packets_loop_accepts data parts (by omega) (alloc.vec.Vec.new packet.Packet)
    0#usize 0#usize ⟨[], parts, [], data.val, by simp, by simp, by simp, simple,
      by simp [alloc.vec.Vec.new], by simp [alloc.vec.Vec.new], by simp⟩
  step with loop_accepts as ⟨ out, fail1, no_fail, one_piece, mapped ⟩
  subst no_fail
  exact (WP.spec_ok _).mpr ⟨out, rfl, one_piece, mapped⟩

/-- An accepted signature packet is well formed. -/
theorem accepted_signatures_are_well_formed : AcceptedSignaturesAreWellFormed := by
  intro body
  refine WP.spec_mono (signature_reads body) ?_
  intro r read signature found
  obtain ⟨version, _, algo_is, _, hashed_off, hashed_len, hashed_inside, unhashed_off,
    unhashed_len, unhashed_inside, _, _, _, values_from, hashed_subs, unhashed_subs, hashed_made,
    unhashed_made, _, _, _, _, four_bytes, known, _⟩ := read signature found
  have hashed_end : signature.hashed.off.val + signature.hashed.len.val = HashedEnd body.val := by
    simp only [HashedEnd]
    omega
  have unhashed_end : signature.unhashed.off.val + signature.unhashed.len.val =
      UnhashedEnd body.val := by
    simp only [UnhashedEnd, ← hashed_end]
    omega
  have unhashed_start : signature.unhashed.off.val = HashedEnd body.val + 2 := by omega
  rw [hashed_end] at hashed_made hashed_inside
  refine ⟨version, hashed_inside, ⟨hashed_subs, by rw [← hashed_off]; exact hashed_made,
    fun sub member => ⟨four_bytes sub member, known sub member⟩⟩, by omega,
    ⟨unhashed_subs, by rw [← unhashed_start, ← unhashed_end]; exact unhashed_made⟩, ?_⟩
  rw [← algo_is, ← unhashed_end]
  exact values_from

/-- Two accepted signatures that agree up to the end of the hashed area have the same times and key
flags. -/
theorem signatures_that_agree_up_to_the_hashed_area_have_the_same_times :
    SignaturesThatAgreeUpToTheHashedAreaHaveTheSameTimes := by
  intro body body' signature signature' accepted accepted' same
  have read := signature_reads body
  have read' := signature_reads body'
  rw [accepted] at read
  rw [accepted'] at read'
  rw [WP.spec_ok] at read read'
  exact signatures_that_agree_say_the_same body.val body'.val signature signature'
    (read signature rfl) (read' signature' rfl) same

end SigparseCore
