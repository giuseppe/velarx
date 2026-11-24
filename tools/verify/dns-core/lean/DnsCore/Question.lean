-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `read_name` and `question` do: `question` gives the question of a
-- query exactly when `QueryWith` says the message has one, and then gives what `IsTheQuestion`
-- says.
--
-- Why it is needed: `question` is read by `parse` and by `reply`; it is the one place where the
-- bytes of a query become a `Question`.
--
-- Read before this file: Spec.lean, Words.lean, Flags.lean, NameLoop.lean, and `question` in
-- lib.rs.
--
-- Notation: `cases o with | none | some v` is the two cases of an option; `obtain ⟨a, b⟩ := h`
-- takes `h` apart; `step with t as ⟨ x, hx ⟩` runs one Rust line with the fact `t` and names its
-- result `x` and what is known of it `hx`.
import DnsCore.NameLoop
import DnsCore.Flags
import DnsCore.Words

open Aeneas Aeneas.Std Result velarx_dns_core

namespace DnsCore

/-- `read_name` gives the name after the header and the place where it ends, or `None` when no
good name is there. -/
theorem read_name_reads (m : Slice Std.U8) (has_a_header : 12 ≤ m.length) :
    read_name m ⦃ r =>
      (∀ written off, r = some (written, off) → ∃ labels, GoodName labels ∧
        Bytes written.val = Dotted labels ∧ 12 ≤ off.val ∧ off.val ≤ m.length ∧
        (Bytes m.val).drop 12 = OnWire labels ++ (Bytes m.val).drop off.val) ∧
      (r = none → NoName (Bytes m.val)) ⦄ := by
  unfold read_name
  step with name_loop_reads_the_name m has_a_header as ⟨ written, off, ok', found, not_found ⟩
  split
  · rename_i is_ok
    simp only [WP.spec_ok]
    refine ⟨fun w o same => ?_, fun h => by simp at h⟩
    simp only [Option.some.injEq, Prod.mk.injEq] at same
    obtain ⟨rfl, rfl⟩ := same
    exact found is_ok
  · rename_i not_ok
    simp only [WP.spec_ok]
    exact ⟨fun _ _ h => by simp at h, fun _ => not_found (by simpa using not_ok)⟩

/-- `question` gives the question of the message when it is a query with a question that can be
read (`QueryWith`), and gives it as `IsTheQuestion` says; it gives `None` when there is none. -/
theorem question_reads (m : Slice Std.U8) :
    question m ⦃ r =>
      (∀ q, r = some q → ∃ labels tail, QueryWith (Bytes m.val) labels tail ∧
        IsTheQuestion q (Bytes m.val) labels tail) ∧
      (r = none → ¬ ∃ labels tail, QueryWith (Bytes m.val) labels tail) ⦄ := by
  unfold question
  have h12 := header_is_12
  have len_same : (↑m : List Std.U8).length = m.length := rfl
  step with get16_reads m 2#usize as ⟨ o, flags_read, flags_missing ⟩
  cases o with
  | none =>
    simp only [WP.spec_ok]
    refine ⟨fun _ h => by simp at h, fun _ ⟨labels, tail, query⟩ => ?_⟩
    have := flags_missing rfl
    have := query.has_a_header
    simp only [bytes_length] at this
    scalar_tac
  | some flags =>
    dsimp only
    obtain ⟨_, flags_are⟩ := flags_read flags rfl
    split
    · -- the message is shorter than a header
      rename_i short
      simp only [WP.spec_ok]
      refine ⟨fun _ h => by simp at h, fun _ ⟨labels, tail, query⟩ => ?_⟩
      have := query.has_a_header
      simp only [bytes_length] at this
      scalar_tac
    · rename_i has_a_header
      simp only [lift, bind_ok]
      split
      · -- the response bit is set
        rename_i response
        simp only [WP.spec_ok]
        refine ⟨fun _ h => by simp at h, fun _ ⟨labels, tail, query⟩ => ?_⟩
        have clear := (response_bit_clear flags).mpr (flags_are ▸ query.not_a_response)
        simp [clear] at response
      · rename_i not_response
        have clear : flags &&& FLAG_QR = 0#u16 := by
          simpa only [bne_iff_ne, ne_eq, not_not] using not_response
        have below := (response_bit_clear flags).mp clear
        step with get16_reads m 4#usize as ⟨ o1, count_read, count_missing ⟩
        have header : 12 ≤ m.length := by scalar_tac
        cases o1 with
        | none =>
          simp only [bind_ok, Bool.false_eq_true, ↓reduceIte, WP.spec_ok]
          refine ⟨fun _ h => by simp at h, fun _ ⟨labels, tail, query⟩ => ?_⟩
          have := count_missing rfl
          have := query.has_a_header
          simp only [bytes_length] at this
          omega
        | some count =>
          obtain ⟨_, count_is⟩ := count_read count rfl
          dsimp only
          split
          · -- the count is 1
            rename_i is_one
            simp only [bind_ok, ite_true]
            have count_one : Word (Bytes m.val) 4 = 1 := count_is.symm
            step with read_name_reads m header as ⟨ o2, found, not_found ⟩
            cases o2 with
            | none =>
              simp only [WP.spec_ok]
              refine ⟨fun _ h => by simp at h, fun _ ⟨labels, tail, query⟩ => ?_⟩
              exact not_found rfl labels tail query.name_is_good query.name_follows_the_header
            | some name_and_end =>
              obtain ⟨written, off⟩ := name_and_end
              dsimp only
              obtain ⟨labels, good_name, written_is, ge12, within, same_bytes⟩ :=
                found written off rfl
              -- after the name, the query has nothing else that can be read
              have the_tail : ∀ labels' tail', QueryWith (Bytes m.val) labels' tail' →
                  tail' = (Bytes m.val).drop off.val ∧ off.val + 4 ≤ m.length := by
                intro labels' tail' query
                obtain ⟨_, same_tail⟩ := name_on_wire_is_unique labels labels' _ tail' good_name
                  query.name_is_good (same_bytes.symm.trans query.name_follows_the_header)
                have := query.type_and_class_follow
                rw [← same_tail] at this
                simp only [List.length_drop, bytes_length] at this
                exact ⟨same_tail.symm, by omega⟩
              have name_length := congrArg List.length same_bytes
              simp only [OnWire, List.length_drop, List.length_append, bytes_length] at name_length
              have good_length := good_name.2
              have off_small : off.val ≤ 267 := by
                simp only [OnWire, List.length_append] at good_length
                omega
              have usize_big : 1000 ≤ Usize.max := by scalar_tac
              step with get16_reads m 0#usize as ⟨ o3, id_read, id_missing ⟩
              step with get16_reads m off as ⟨ o4, type_read, type_missing ⟩
              step as ⟨ after_type, after_type_post ⟩
              step with get16_reads m after_type as ⟨ o5, class_read, class_missing ⟩
              cases o3 with
              | none => exact absurd (id_missing rfl) (by scalar_tac)
              | some id =>
                cases o4 with
                | none =>
                  simp only [WP.spec_ok]
                  refine ⟨fun _ h => by simp at h, fun _ ⟨labels', tail', query⟩ => ?_⟩
                  have := (the_tail labels' tail' query).2
                  exact type_missing rfl (by omega)
                | some qtype =>
                  cases o5 with
                  | none =>
                    simp only [WP.spec_ok]
                    refine ⟨fun _ h => by simp at h, fun _ ⟨labels', tail', query⟩ => ?_⟩
                    have := (the_tail labels' tail' query).2
                    exact class_missing rfl (by omega)
                  | some qclass =>
                    obtain ⟨_, id_is⟩ := id_read id rfl
                    obtain ⟨type_there, qtype_is⟩ := type_read qtype rfl
                    obtain ⟨class_there, qclass_is⟩ := class_read qclass rfl
                    step as ⟨ end_of_it, end_post ⟩
                    refine ⟨fun q is_q => ?_, fun h => by simp at h⟩
                    simp only [Option.some.injEq] at is_q
                    subst is_q
                    refine ⟨labels, (Bytes m.val).drop off.val,
                      ⟨by simpa using header, ?_, count_one, same_bytes, ?_, good_name⟩, ?_⟩
                    · exact flags_are ▸ below
                    · simp only [List.length_drop, bytes_length]
                      omega
                    · refine ⟨id_is, flags_are, written_is, ?_, ?_, ?_⟩
                      · show qtype.val = _
                        rw [word_of_the_rest, Nat.add_zero]
                        exact qtype_is
                      · show qclass.val = _
                        rw [word_of_the_rest, qclass_is]
                        congr 1
                      · simp only [QuestionEnd, OnWire, List.length_append] at name_length ⊢
                        omega
          · -- the count is not 1
            rename_i not_one
            simp only [bind_ok, Bool.false_eq_true, ↓reduceIte, WP.spec_ok]
            refine ⟨fun _ h => by simp at h, fun _ ⟨labels, tail, query⟩ => ?_⟩
            have := query.one_question
            exact not_one (UScalar.eq_of_val_eq (count_is.trans this))

end DnsCore
