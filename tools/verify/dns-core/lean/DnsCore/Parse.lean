-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `parse` does: it follows the Rust function, line by line (the flags,
-- the counts of answers and authority records, the question, the operation code), and at each
-- answer uses the matching fact of ParseVerdicts.lean.
--
-- Why it is needed: this is the proof of `ParseSaysExactly`.
--
-- Read before this file: Spec.lean, Question.lean, ParseVerdicts.lean, and `parse` in lib.rs.
--
-- Notation: as in Question.lean; `split` makes one case of each `if`.
import DnsCore.Question
import DnsCore.ParseVerdicts

open Aeneas Aeneas.Std Result velarx_dns_core

namespace DnsCore

/-- `parse` drops a message that is short or a response, refuses FORMERR when a count of answers
or of authority records is not 0 or `question` finds no question, refuses NOTIMP when the operation
code is not 0, and gives the query otherwise: that is `ParseIs`, of every message. -/
theorem parse_answers_as_parse_is (m : Slice Std.U8) :
    parse m ⦃ r => ParseIs (Bytes m.val) r ⦄ := by
  unfold parse
  have h12 := header_is_12
  have len_same : (↑m : List Std.U8).length = m.length := rfl
  step with get16_reads m 2#usize as ⟨ o, flags_read, flags_missing ⟩
  cases o with
  | none =>
    simp only [WP.spec_ok]
    refine parse_drops _ (Or.inl ?_)
    have := flags_missing rfl
    simp only [bytes_length]
    omega
  | some flags =>
    obtain ⟨_, flags_are⟩ := flags_read flags rfl
    simp only
    split
    · rename_i has_a_header
      have header : 12 ≤ m.length := by scalar_tac
      simp only [lift, bind_ok]
      split
      · -- the response bit is clear
        rename_i clear
        have below : flags.val < 32768 :=
          (response_bit_clear flags).mp (by simpa using clear)
        have not_dropped : ¬ Dropped (Bytes m.val) := by
          rintro (short | response)
          · simp only [bytes_length] at short
            omega
          · omega
        step with get16_reads m 6#usize as ⟨ o1, answers_read, answers_missing ⟩
        have present : ∃ answers, o1 = some answers := by
          cases o1 with
          | none => exact absurd (answers_missing rfl) (by scalar_tac)
          | some a => exact ⟨a, rfl⟩
        obtain ⟨answers, rfl⟩ := present
        obtain ⟨_, answers_are⟩ := answers_read answers rfl
        dsimp only
        split
        · -- the count of answers is 0
          rename_i is_zero
          have no_answers : Word (Bytes m.val) 6 = 0 := answers_are.symm
          simp only [bind_ok, ite_true]
          step with get16_reads m 8#usize as ⟨ o2, authority_read, authority_missing ⟩
          have present : ∃ authority, o2 = some authority := by
            cases o2 with
            | none => exact absurd (authority_missing rfl) (by scalar_tac)
            | some a => exact ⟨a, rfl⟩
          obtain ⟨authority, rfl⟩ := present
          obtain ⟨_, authority_are⟩ := authority_read authority rfl
          dsimp only
          split
          · -- the count of authority records is 0
            rename_i is_zero
            have no_authority : Word (Bytes m.val) 8 = 0 := authority_are.symm
            simp only [bind_ok, ite_true]
            have no_records : ¬ HasRecords (Bytes m.val) := by
              rintro (records | records)
              · exact records no_answers
              · exact records no_authority
            step with question_reads m as ⟨ o3, question_is, no_question ⟩
            cases o3 with
            | none =>
              simp only [WP.spec_ok]
              exact parse_refuses_a_form _ not_dropped (Or.inr (no_question rfl))
            | some q =>
              obtain ⟨labels, tail, query, is_the_question⟩ := question_is q rfl
              dsimp only
              split
              · -- an operation code other than 0
                rename_i other_opcode
                simp only [WP.spec_ok]
                refine parse_refuses_an_opcode _ not_dropped no_records ⟨labels, tail, query⟩ ?_
                rw [← flags_are]
                intro no_opcode
                have := (opcode_clear flags).mpr no_opcode
                simp [this] at other_opcode
              · rename_i no_opcode
                simp only [WP.spec_ok]
                have : flags &&& OPCODE = 0#u16 := by
                  simpa only [bne_iff_ne, ne_eq, not_not] using no_opcode
                exact parse_answers_a_query _ q not_dropped no_records
                  (flags_are ▸ (opcode_clear flags).mp this) labels tail query is_the_question
          · -- authority records
            rename_i some_authority
            simp only [bind_ok, Bool.false_eq_true, ↓reduceIte, WP.spec_ok]
            refine parse_refuses_a_form _ not_dropped (Or.inl (Or.inr ?_))
            rw [← authority_are]
            intro is_zero
            exact some_authority (UScalar.eq_of_val_eq is_zero)
        · -- answer records
          rename_i some_answers
          simp only [bind_ok, Bool.false_eq_true, ↓reduceIte, WP.spec_ok]
          refine parse_refuses_a_form _ not_dropped (Or.inl (Or.inl ?_))
          rw [← answers_are]
          intro is_zero
          exact some_answers (UScalar.eq_of_val_eq is_zero)
      · -- the response bit is set
        rename_i set
        simp only [WP.spec_ok]
        refine parse_drops _ (Or.inr ?_)
        have : ¬ flags.val < 32768 := fun below =>
          set (by simpa using (response_bit_clear flags).mpr below)
        omega
    · -- shorter than a header
      rename_i short
      simp only [WP.spec_ok]
      refine parse_drops _ (Or.inl ?_)
      simp only [bytes_length]
      scalar_tac

end DnsCore
