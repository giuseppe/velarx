-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `reply` builds: for a query with a question that can be read and a
-- size that fits it, the bytes `IsTheReply` (Spec.lean) says.
--
-- Why it is needed: this is the proof of the claims about `reply`.  It follows the Rust function:
-- the question, the limit, the copy of the question, the records, the flags, the four writes of the
-- header; then each field of `IsTheReply` is read off the bytes.
--
-- Read before this file: Spec.lean, Question.lean, RecordLoops.lean, NewHeader.lean, Flags.lean,
-- and `reply` in lib.rs.
--
-- Notation: as in Question.lean.
import DnsCore.Question
import DnsCore.EncodeLabels
import DnsCore.RecordLoops
import DnsCore.NewHeader
import DnsCore.Flags
import DnsCore.ParseVerdicts

open Aeneas Aeneas.Std Result velarx_dns_core

namespace DnsCore

/-- The loop of `reply` that copies the question copies the first bytes of the message. -/
theorem copy_question_loop_copies (m : Slice Std.U8) (stop : Std.Usize) (out : alloc.vec.Vec Std.U8)
    (start : Std.Usize) (in_order : start.val ≤ stop.val) (inside : stop.val ≤ m.length)
    (room : out.length + (stop.val - start.val) ≤ 65535) :
    reply_loop0 m stop out start ⦃ r =>
      Bytes r.val =
        Bytes out.val ++ ((Bytes m.val).drop start.val).take (stop.val - start.val) ⦄ := by
  have := copy_loop_copies m out stop start in_order inside room
  unfold encode_name_loop0_loop0 encode_name_loop0_loop0.body at this
  unfold reply_loop0 reply_loop0.body
  exact this

/-- The limit of `reply` is the size, or 65535 if that is less. -/
theorem reply_limit (out_size : Std.Usize) :
    (if out_size < MAX_MESSAGE then ok out_size else ok MAX_MESSAGE) ⦃ limit =>
      limit.val = min out_size.val 65535 ⦄ := by
  have : MAX_MESSAGE.val = 65535 := by simp [global_simps]
  split
  · simp only [WP.spec_ok]
    scalar_tac
  · simp only [WP.spec_ok]
    scalar_tac

/-- `reply` gives nothing when `question` finds no question or the question is longer than the
limit, and otherwise the reply that `IsTheReply` says: the query's id and question, the records
that fit, the count and the flags. -/
theorem reply_builds_the_reply (m : Slice Std.U8) (rcode : Std.U16) (authoritative : Bool)
    (out_size : Std.Usize) (rrs : Slice Rr) :
    reply m rcode authoritative out_size rrs ⦃ r =>
      (∀ out, r = some out → ∃ labels tail, QueryWith (Bytes m.val) labels tail ∧
        QuestionEnd labels ≤ min out_size.val 65535 ∧
        IsTheReply (Bytes out.val) (Bytes m.val) rcode.val authoritative (min out_size.val 65535)
          rrs.val labels tail) ∧
      (r = none → ¬ ∃ labels tail, QueryWith (Bytes m.val) labels tail ∧
        QuestionEnd labels ≤ min out_size.val 65535) ⦄ := by
  unfold reply
  step with question_reads m as ⟨ o, question_is, no_question ⟩
  cases o with
  | none =>
    simp only [WP.spec_ok]
    exact ⟨fun _ h => by simp at h,
      fun _ ⟨labels, tail, query, _⟩ => no_question rfl ⟨labels, tail, query⟩⟩
  | some q =>
    obtain ⟨labels, tail, query, is_the_question⟩ := question_is q rfl
    dsimp only
    step with reply_limit out_size as ⟨ limit, limit_is ⟩
    have the_end : q.end.val = QuestionEnd labels := is_the_question.ends_after_the_class
    split
    · -- the question does not fit
      rename_i too_big
      simp only [WP.spec_ok]
      refine ⟨fun _ h => by simp at h, fun _ ⟨labels', tail', query', fits⟩ => ?_⟩
      obtain ⟨rfl, rfl⟩ := the_reading_is_unique _ labels labels' tail tail' query query'
      scalar_tac
    · rename_i fits
      have usize_big : 100000 ≤ Usize.max := by scalar_tac
      have qend_inside := the_question_is_inside _ labels tail query
      simp only [bytes_length] at qend_inside
      have len_same : (↑m : List Std.U8).length = m.length := rfl
      step with copy_question_loop_copies m q.end (alloc.vec.Vec.new Std.U8) 0#usize
        (by scalar_tac) (by omega) (by simp; scalar_tac) as ⟨ question_bytes, question_copied ⟩
      have bytes_of_new : Bytes (alloc.vec.Vec.new Std.U8).val = [] := rfl
      rw [bytes_of_new, List.nil_append, Nat.sub_zero, List.drop_zero] at question_copied
      have the_question_length : question_bytes.val.length = QuestionEnd labels := by
        have := congrArg List.length question_copied
        rw [List.length_take] at this
        simp only [bytes_length] at qend_inside this
        omega
      have qend_le_limit : QuestionEnd labels ≤ limit.val := by scalar_tac
      have question_vec_length := vec_length_is_the_list_length question_bytes
      step with records_loop_writes_whole_records rrs limit question_bytes (by omega) (by omega)
        as ⟨ out1, count, cut, written, written_fits, count_fits, cut_is, stopped ⟩
      simp only [lift, bind_ok]
      have base_value := base_flags_value q.flags rcode
      generalize FLAG_QR ||| FLAG_RA ||| q.flags &&& FLAG_RD ||| rcode &&& RCODE = base
        at base_value ⊢
      have bit_is_small : Bit q.flags.val 8 ≤ 1 := by
        unfold Bit
        omega
      have code_is_small : rcode.val % 16 < 16 := Nat.mod_lt _ (by omega)
      have base_clear : base.val % 2048 < 1024 := by omega
      step with authoritative_bit_is_added base authoritative base_clear as ⟨ flags1, flags1_value ⟩
      have flags1_clear : flags1.val % 1024 < 512 := by
        have : (if authoritative = true then 1024 else 0) = 0 ∨
            (if authoritative = true then 1024 else 0) = 1024 := by
          split <;> simp
        omega
      step with truncation_bit_is_added flags1 cut flags1_clear as ⟨ flags2, flags2_value ⟩
      have out1_length : out1.length ≥ QuestionEnd labels := by
        have := congrArg List.length written
        simp only [bytes_length, List.length_append] at this
        rw [vec_length_is_the_list_length]
        omega
      have question_is_long : 17 ≤ QuestionEnd labels := by
        have : 1 ≤ (OnWire labels).length := by simp [OnWire]
        unfold QuestionEnd
        omega
      simp only [alloc.vec.Vec.deref_mut]
      have header_length : out1.slice.length ≥ 12 := by
        have : out1.slice.length = out1.length := rfl
        omega
      have sets_keep_the_length : ∀ (before after : Slice Std.U8) (k : Nat) (a b : Nat),
          Bytes after.val = (((Bytes before.val).set k a).set (k + 1) b) →
          after.length = before.length := fun before after k a b is_set => by
        have := congrArg List.length is_set
        simpa using this
      step with put16_sets out1.slice 2#usize flags2 (by scalar_tac) as ⟨ s1, s1_is ⟩
      have s1_length := sets_keep_the_length _ _ _ _ _ s1_is
      step with put16_sets s1 6#usize count (by scalar_tac) as ⟨ s3, s3_is ⟩
      have s3_length := sets_keep_the_length _ _ _ _ _ s3_is
      step with put16_sets s3 8#usize 0#u16 (by scalar_tac) as ⟨ s5, s5_is ⟩
      have s5_length := sets_keep_the_length _ _ _ _ _ s5_is
      step with put16_sets s5 10#usize 0#u16 (by scalar_tac) as ⟨ s7, s7_is ⟩
      -- the bytes of the reply: the bytes written, with the new header
      have the_reply : Bytes s7.val = NewHeader (Bytes out1.val) flags2.val count.val := by
        rw [s7_is, s5_is, s3_is, s1_is]
        simp [NewHeader, show out1.slice.val = out1.val from rfl]
      have flags_fit : flags2.val < 65536 := by scalar_tac
      have count_fit : count.val < 65536 := by scalar_tac
      have out1_long : 12 ≤ (Bytes out1.val).length := by
        simp only [bytes_length]
        have : out1.length = out1.val.length := rfl
        omega
      obtain ⟨new_length, new_id, new_flags, new_one, new_count, new_authority, new_additional,
        new_rest⟩ := new_header_says (Bytes out1.val) flags2.val count.val out1_long flags_fit
          count_fit
      refine ⟨fun out same => ?_, fun h => by simp at h⟩
      obtain rfl := Option.some.inj same
      have qend_le : QuestionEnd labels ≤ min out_size.val 65535 := by
        scalar_tac
      refine ⟨labels, tail, query, qend_le, ?_⟩
      have question_prefix :
          Bytes question_bytes.val = (Bytes m.val).take (QuestionEnd labels) := by
        rw [question_copied, the_end]
      have the_bytes : Bytes out1.val = (Bytes m.val).take (QuestionEnd labels) ++
          (rrs.val.take count.val).flatMap RecordOf := by
        rw [written, question_prefix]
      have qend_in_bytes : QuestionEnd labels ≤ (Bytes m.val).length := by
        simpa using qend_inside
      have take_length : ((Bytes m.val).take (QuestionEnd labels)).length = QuestionEnd labels :=
        List.length_take_of_le qend_in_bytes
      have H_is_long : (Bytes out1.val).length = out1.length := by simp
      have the_end_of_question : ∀ k, k + 2 ≤ QuestionEnd labels →
          Word (Bytes out1.val) k = Word (Bytes m.val) k := fun k inside => by
        rw [the_bytes, word_of_a_beginning _ _ _ (by omega),
          word_of_a_prefix _ _ _ inside qend_in_bytes]
      show IsTheReply (Bytes s7.val) _ _ _ _ _ _ _
      rw [the_reply]
      refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
      · -- the size
        rw [new_length, H_is_long]
        scalar_tac
      · -- the id
        rw [new_id, the_end_of_question 0 (by omega)]
      · -- the question
        have after_header : (Bytes m.val).drop 12 = OnWire labels ++ tail :=
          query.name_follows_the_header
        have name_length : QuestionEnd labels - 12 = (OnWire labels).length + 4 := by
          unfold QuestionEnd
          omega
        rw [new_rest, the_bytes, List.drop_append_of_le_length (by omega),
          List.take_append_of_le_length (by simp [take_length]), List.take_of_length_le
            (by simp [take_length]), List.drop_take, after_header, name_length, List.take_append]
        simp
      · -- one question
        rw [new_one, the_end_of_question 4 (by omega)]
        exact query.one_question
      · -- the records
        rw [new_count]
        have drop_the_question : (NewHeader (Bytes out1.val) flags2.val count.val).drop
            (QuestionEnd labels) = (Bytes out1.val).drop (QuestionEnd labels) := by
          have := congrArg (List.drop (QuestionEnd labels - 12)) new_rest
          rwa [List.drop_drop, List.drop_drop, Nat.add_sub_cancel' (by omega)] at this
        rw [drop_the_question, the_bytes, List.drop_left' take_length]
      · -- the count
        rw [new_count]
        exact count_fits
      · -- no other sections
        exact ⟨new_authority, new_additional⟩
      · -- the flags
        rw [new_flags, new_count, flags2_value, flags1_value, base_value,
          is_the_question.flags_are_the_second_word]
        by_cases written_everything : cut = true
        · have left_out := cut_is.mp written_everything
          simp [written_everything, left_out]
          omega
        · have all_written : ¬ count.val < rrs.length := fun left_out =>
            written_everything (cut_is.mpr left_out)
          simp [written_everything, all_written]
          omega
      · -- the last record is the one that does not fit
        intro rr is_rr
        rw [new_count] at is_rr
        have left_out : count.val < rrs.length :=
          (List.getElem?_eq_some_iff.mp is_rr).1
        have := stopped (cut_is.mpr left_out) rr is_rr
        rw [new_length, H_is_long]
        omega

end DnsCore
