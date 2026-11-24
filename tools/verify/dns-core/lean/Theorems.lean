-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the list of what is proved of crates/dns-core.  The statements are in
-- DnsCore/Spec.lean, the proofs in DnsCore/Claims.lean (which uses the files before it in
-- DnsCore/).
-- ../../run ends on this file: it fails unless every line `#proved T` below
-- prints "proved: T".
--
-- Why it is needed: Lean checks a proof when it is read, but nothing
-- says that the theorem is the one of the statement or that no `sorry`
-- or new axiom is behind it.  `#proved T` (../../Proved.lean) prints the
-- axioms `T` rests on and fails unless they are the three of Lean and the
-- library functions the crate has no model of (there are none: the crate calls no such function).
--
-- Read before this file: DnsCore/Spec.lean.
import Proved
import DnsCore.Claims

-- Each theorem is a proof of the statement of that name in Spec.lean: Lean
-- checks the type of each line below, so Theorems.lean and Spec.lean suffice.
example : DnsCore.NothingPanics :=
  DnsCore.nothing_panics
example : DnsCore.QuestionIsReadExactlyWhenReadable :=
  DnsCore.question_is_read_exactly_when_readable
example : DnsCore.ThereIsOneReading :=
  DnsCore.there_is_one_reading
example : DnsCore.ParseSaysExactly :=
  DnsCore.parse_says_exactly
example : DnsCore.ErrorReplyIsAHeader :=
  DnsCore.error_reply_is_a_header_of_twelve_bytes
example : DnsCore.ReplyAnswersExactlyWhenTheQuestionFits :=
  DnsCore.reply_answers_exactly_when_the_question_fits
example : DnsCore.ReplyIs :=
  DnsCore.reply_is_the_reply
example : DnsCore.ReplyFitsTheSize :=
  DnsCore.reply_fits_the_size
example : DnsCore.ReplyEchoesTheQuery :=
  DnsCore.reply_echoes_the_query
example : DnsCore.ReplyCountsWholeRecords :=
  DnsCore.reply_counts_whole_records
example : DnsCore.ReplyFlagsAreAsAsked :=
  DnsCore.reply_flags_are_as_asked
example : DnsCore.EncodeNameWritesTheWire :=
  DnsCore.encode_name_writes_exactly_the_names_that_can_be_written
example : DnsCore.AQuestionNameCanBeWrittenBack :=
  DnsCore.a_question_name_is_written_back

#proved DnsCore.nothing_panics
#proved DnsCore.question_is_read_exactly_when_readable
#proved DnsCore.there_is_one_reading
#proved DnsCore.parse_says_exactly
#proved DnsCore.error_reply_is_a_header_of_twelve_bytes
#proved DnsCore.reply_answers_exactly_when_the_question_fits
#proved DnsCore.reply_is_the_reply
#proved DnsCore.reply_fits_the_size
#proved DnsCore.reply_echoes_the_query
#proved DnsCore.reply_counts_whole_records
#proved DnsCore.reply_flags_are_as_asked
#proved DnsCore.encode_name_writes_exactly_the_names_that_can_be_written
#proved DnsCore.a_question_name_is_written_back
