-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the claims of Spec.lean, one theorem for each, in the order
-- of Spec.lean, and two examples that the definitions of Spec.lean can be met.
--
-- Why it is needed: ../Theorems.lean names what is proved; the proofs are here.  They are short
-- because the work is in the files before this one.
--
-- Read before this file: Spec.lean, then the file of each function.
--
-- Notation: `WP.spec_mono h f` is "use what `h` says of the function, and `f` to show that it is
-- enough".
import DnsCore.Parse
import DnsCore.ErrorReply
import DnsCore.Reply
import DnsCore.RoundTrip

open Aeneas Aeneas.Std Result velarx_dns_core

namespace DnsCore

/-- Each of the five functions returns, whatever the bytes and the sizes: the lemma of each of them
(one in each of the files before this one) says so, and this reads it off. -/
theorem nothing_panics : NothingPanics := by
  refine ⟨fun m => ?_, fun m => ?_, fun m rcode => ?_, fun text => ?_,
    fun m rcode authoritative out_size rrs => ?_⟩
  · exact WP.spec_mono (question_reads m) (fun _ _ => trivial)
  · exact WP.spec_mono (parse_answers_as_parse_is m) (fun _ _ => trivial)
  · exact WP.spec_mono (error_reply_is_a_header m rcode) (fun _ _ => trivial)
  · exact WP.spec_mono (encode_name_writes_the_wire text) (fun _ _ => trivial)
  · exact WP.spec_mono (reply_builds_the_reply m rcode authoritative out_size rrs)
      (fun _ _ => trivial)

/-- `question_reads` (Question.lean) says what `question` gives; a message that has a question
that can be read is not refused, because a refusal says there is none. -/
theorem question_is_read_exactly_when_readable : QuestionIsReadExactlyWhenReadable :=
  fun m => WP.spec_mono (question_reads m) fun r reads =>
    ⟨reads.1, fun ⟨labels, tail, query⟩ => by
      cases r with
      | none => exact absurd ⟨labels, tail, query⟩ (reads.2 rfl)
      | some q => exact ⟨q, rfl⟩⟩

/-- A query has one reading: `the_reading_is_unique` (ParseVerdicts.lean). -/
theorem there_is_one_reading : ThereIsOneReading :=
  fun m labels labels' tail tail' first second =>
    the_reading_is_unique m labels labels' tail tail' first second

/-- What `parse` answers is `ParseIs` of the message (Parse.lean). -/
theorem parse_says_exactly : ParseSaysExactly :=
  fun m => parse_answers_as_parse_is m

/-- What `error_reply` builds is a header (ErrorReply.lean). -/
theorem error_reply_is_a_header_of_twelve_bytes : ErrorReplyIsAHeader :=
  fun m rcode => error_reply_is_a_header m rcode

/-- `reply_builds_the_reply` (Reply.lean) says that a reply has the question that can be read
and the size that fits it, and that a refusal has none; this puts the two together. -/
theorem reply_answers_exactly_when_the_question_fits : ReplyAnswersExactlyWhenTheQuestionFits :=
  fun m rcode authoritative out_size rrs =>
    WP.spec_mono (reply_builds_the_reply m rcode authoritative out_size rrs) fun r built =>
      ⟨fun out answered => by
        obtain ⟨labels, tail, query, fits, _⟩ := built.1 out answered
        exact ⟨labels, tail, query, fits⟩,
      fun ⟨labels, tail, query, fits⟩ => by
        cases r with
        | none => exact absurd ⟨labels, tail, query, fits⟩ (built.2 rfl)
        | some out => exact ⟨out, rfl⟩⟩

/-- `reply_builds_the_reply` (Reply.lean) says it. -/
theorem reply_is_the_reply : ReplyIs :=
  fun m rcode authoritative out_size rrs =>
    WP.spec_mono (reply_builds_the_reply m rcode authoritative out_size rrs) fun r built out
        answered => by
      obtain ⟨labels, tail, query, _, reply⟩ := built.1 out answered
      exact ⟨labels, tail, query, reply⟩

/-- The reply is not longer than the limit, which is the size or 65535: a field of `IsTheReply`. -/
theorem reply_fits_the_size : ReplyFitsTheSize :=
  fun m rcode authoritative out_size rrs =>
    WP.spec_mono (reply_builds_the_reply m rcode authoritative out_size rrs) fun r built out
        answered => by
      obtain ⟨_, _, _, _, reply⟩ := built.1 out answered
      have := reply.fits_the_limit
      simp only [bytes_length] at this
      have := vec_length_is_the_list_length out
      omega

/-- The id, the count of questions and the question bytes of the reply are fields of
`IsTheReply`. -/
theorem reply_echoes_the_query : ReplyEchoesTheQuery :=
  fun m rcode authoritative out_size rrs =>
    WP.spec_mono (reply_builds_the_reply m rcode authoritative out_size rrs) fun r built out
        answered => by
      obtain ⟨labels, tail, query, _, reply⟩ := built.1 out answered
      exact ⟨labels, tail, query, reply.echoes_the_id, reply.has_one_question,
        reply.echoes_the_question⟩

/-- The records, their count and the stop at the first that does not fit are fields of
`IsTheReply`; the truncation bit is read off the flags, which are their sum. -/
theorem reply_counts_whole_records : ReplyCountsWholeRecords :=
  fun m rcode authoritative out_size rrs =>
    WP.spec_mono (reply_builds_the_reply m rcode authoritative out_size rrs) fun r built out
        answered => by
      obtain ⟨labels, tail, query, _, reply⟩ := built.1 out answered
      refine ⟨labels, tail, query, reply.counts_no_more_than_it_was_given,
        reply.records_are_whole, ?_, ?_⟩
      · have flags := reply.flags_are
        have : Bit (Word (Bytes m.val) 2) 8 ≤ 1 := by
          unfold Bit
          omega
        have : rcode.val % 16 < 16 := Nat.mod_lt _ (by omega)
        have : (↑rrs : List Rr).length = rrs.length := rfl
        unfold Bit
        rw [flags]
        simp only [Nat.reducePow]
        split <;> split <;> omega
      · intro rr is_rr
        have := reply.stops_only_when_full rr is_rr
        simpa [vec_length_is_the_list_length] using this

/-- The flags are a field of `IsTheReply`. -/
theorem reply_flags_are_as_asked : ReplyFlagsAreAsAsked :=
  fun m rcode authoritative out_size rrs =>
    WP.spec_mono (reply_builds_the_reply m rcode authoritative out_size rrs) fun r built out
        answered => by
      obtain ⟨_, _, _, _, reply⟩ := built.1 out answered
      exact reply.flags_are

/-- `encode_name_writes_the_wire` (EncodeName.lean) says what it gives, and that a name that can
be written is not refused. -/
theorem encode_name_writes_exactly_the_names_that_can_be_written : EncodeNameWritesTheWire :=
  fun text => WP.spec_mono (encode_name_writes_the_wire text) fun r wrote =>
    ⟨wrote.1, fun ⟨labels, writable, joined⟩ => by
      cases r with
      | none => exact absurd ⟨labels, writable, joined⟩ (wrote.2 rfl)
      | some wire => exact ⟨wire, rfl⟩⟩

/-- The round trip is proved in RoundTrip.lean. -/
theorem a_question_name_is_written_back : AQuestionNameCanBeWrittenBack :=
  fun m => a_question_name_can_be_written_back m

/-- `QueryWith` can be met: the query of `web`, type A, class IN, with the id 0x1234 and the bit
of recursion desired (the 12 bytes of the header, `3 w e b 0`, the type, the class). -/
example : QueryWith ([0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0] ++ [3, 119, 101, 98, 0] ++
    [0, 1, 0, 1]) [[119, 101, 98]] [0, 1, 0, 1] := by
  refine ⟨by decide, by decide, by decide, by decide, by decide, ?_, by simp [OnWire]⟩
  intro label inside
  simp only [List.mem_singleton] at inside
  subst inside
  simp [GoodLabel]

/-- `IsTheReply` can be met: the reply to that query (the id, the flags 0x8180: a response with
recursion available and desired, one question, one answer; the question; and the record A 10.0.0.1:
the pointer, the type 1, the class 1, the time to live 60, the length 4, the address) with one
record given, the code 0, not authoritative, at most 512 bytes. -/
example : IsTheReply
    ([0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0] ++ [3, 119, 101, 98, 0, 0, 1, 0, 1] ++
      [192, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 0, 0, 1])
    ([0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0] ++ [3, 119, 101, 98, 0] ++ [0, 1, 0, 1])
    0 false 512
    [⟨1#u16, alloc.vec.Vec.from [10#u8, 0#u8, 0#u8, 1#u8] (by scalar_tac)⟩]
    [[119, 101, 98]] [0, 1, 0, 1] := by
  refine ⟨by decide, by decide, by decide, by decide, ?_, by decide, by decide, by decide, ?_⟩
  · simp [QuestionEnd, OnWire, RecordOf, Bytes, Word]
  · intro rr is_rr
    simp [Word] at is_rr

end DnsCore
