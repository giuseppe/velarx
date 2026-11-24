-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: for each of the four answers of `parse` (no reply, FORMERR, NOTIMP, a
-- query) that `ParseIs` (Spec.lean) holds of the answer when the message is as that answer needs,
-- and that two `Question`s of the same query are the same.
--
-- Why it is needed: `ParseIs` says four "exactly when" at once; once the answer is known, the three
-- others have to be shown false.  Doing it here, once for each answer, keeps the proof of `parse`
-- (Parse.lean) to the steps of the Rust function.
--
-- Read before this file: Spec.lean (`ParseIs`, `Dropped`, `HasRecords`, `HasAQuestion`).
--
-- Notation: `Parsed.Refuse c` is the answer "reply with the code c" of `parse`; `simp [h]` rewrites
-- with `h` and simplifies; `rintro ⟨a, b⟩` takes the hypothesis of a goal `A ∧ B → ...` apart.
import DnsCore.WireNames

open Aeneas Aeneas.Std Result velarx_dns_core

namespace DnsCore

/-- The question of a query is determined by its name and the bytes after it: two `Question`s
that are the question of the same query are the same. -/
theorem the_question_is_unique (q q' : Question) (m : List Nat) (labels : List (List Nat))
    (tail : List Nat) (first : IsTheQuestion q m labels tail)
    (second : IsTheQuestion q' m labels tail) : q = q' := by
  have same_name : q.name = q'.name := by
    apply alloc.vec.Vec.ext
    have := first.name_is_dotted.trans second.name_is_dotted.symm
    exact List.map_injective_iff.mpr (fun a b h => UScalar.eq_of_val_eq h) this
  have same_id : q.id = q'.id :=
    UScalar.eq_of_val_eq (first.id_is_the_first_word.trans second.id_is_the_first_word.symm)
  have same_flags : q.flags = q'.flags :=
    UScalar.eq_of_val_eq
      (first.flags_are_the_second_word.trans second.flags_are_the_second_word.symm)
  have same_type : q.qtype = q'.qtype :=
    UScalar.eq_of_val_eq
      (first.type_follows_the_name.trans second.type_follows_the_name.symm)
  have same_class : q.qclass = q'.qclass :=
    UScalar.eq_of_val_eq
      (first.class_follows_the_type.trans second.class_follows_the_type.symm)
  have same_end : q.end = q'.end :=
    UScalar.eq_of_val_eq (first.ends_after_the_class.trans second.ends_after_the_class.symm)
  cases q
  cases q'
  simp_all

/-- A query has one reading: its name and the bytes after it are determined by its bytes. -/
theorem the_reading_is_unique (m : List Nat) (labels labels' : List (List Nat))
    (tail tail' : List Nat) (first : QueryWith m labels tail) (second : QueryWith m labels' tail') :
    labels = labels' ∧ tail = tail' :=
  name_on_wire_is_unique labels labels' tail tail' first.name_is_good second.name_is_good
    (first.name_follows_the_header.symm.trans second.name_follows_the_header)

/-- The question of a query is inside the message: the header, the name, the type and the class are
all there. -/
theorem the_question_is_inside (m : List Nat) (labels : List (List Nat)) (tail : List Nat)
    (query : QueryWith m labels tail) : QuestionEnd labels ≤ m.length := by
  have := congrArg List.length query.name_follows_the_header
  have := query.type_and_class_follow
  have := query.has_a_header
  simp only [List.length_drop, List.length_append] at *
  unfold QuestionEnd
  omega

/-- The codes of the two refusals are different. -/
theorem formerr_is_not_notimp : RCODE_FORMERR ≠ RCODE_NOTIMP := by
  simp [global_simps]

/-- A dropped message is answered `Drop`. -/
theorem parse_drops (m : List Nat) (dropped : Dropped m) : ParseIs m Parsed.Drop := by
  refine ⟨by simp [dropped], ?_, ?_, ?_⟩ <;> simp [dropped]

/-- A message that is not dropped and has records or no question is refused FORMERR. -/
theorem parse_refuses_a_form (m : List Nat) (not_dropped : ¬ Dropped m)
    (odd : HasRecords m ∨ ¬ HasAQuestion m) : ParseIs m (Parsed.Refuse RCODE_FORMERR) := by
  refine ⟨by simp [not_dropped], by simp [not_dropped, odd], ?_, ?_⟩
  · simp only [Parsed.Refuse.injEq, formerr_is_not_notimp, false_iff]
    rintro ⟨_, no_records, has_question, _⟩
    rcases odd with records | no_question
    · exact no_records records
    · exact no_question has_question
  · intro q
    simp only [reduceCtorEq, false_iff]
    rintro ⟨_, no_records, _, labels, tail, query, _⟩
    rcases odd with records | no_question
    · exact no_records records
    · exact no_question ⟨labels, tail, query⟩

/-- A message that is not dropped, has no records, has a question and an operation code other than
0 is refused NOTIMP. -/
theorem parse_refuses_an_opcode (m : List Nat) (not_dropped : ¬ Dropped m)
    (no_records : ¬ HasRecords m) (has_question : HasAQuestion m)
    (other_opcode : Opcode (Word m 2) ≠ 0) : ParseIs m (Parsed.Refuse RCODE_NOTIMP) := by
  refine ⟨by simp [not_dropped], ?_, by simp [not_dropped, no_records, has_question, other_opcode],
    ?_⟩
  · simp only [Parsed.Refuse.injEq, formerr_is_not_notimp.symm, false_iff]
    rintro ⟨_, records | no_question⟩
    · exact no_records records
    · exact no_question has_question
  · intro q
    simp only [reduceCtorEq, false_iff]
    rintro ⟨_, _, no_opcode, _⟩
    exact other_opcode no_opcode

/-- A message that is not dropped, has no records and has the operation code 0 and a question that
can be read is answered `Query` of that question. -/
theorem parse_answers_a_query (m : List Nat) (q : Question) (not_dropped : ¬ Dropped m)
    (no_records : ¬ HasRecords m) (no_opcode : Opcode (Word m 2) = 0) (labels : List (List Nat))
    (tail : List Nat) (query : QueryWith m labels tail) (question : IsTheQuestion q m labels tail) :
    ParseIs m (Parsed.Query q) := by
  refine ⟨by simp [not_dropped], ?_, ?_, ?_⟩
  · simp only [reduceCtorEq, false_iff, not_and]
    intro _ odd
    rcases odd with records | no_question
    · exact no_records records
    · exact no_question ⟨labels, tail, query⟩
  · simp only [reduceCtorEq, false_iff]
    rintro ⟨_, _, _, other_opcode⟩
    exact other_opcode no_opcode
  · intro q'
    simp only [Parsed.Query.injEq]
    constructor
    · rintro rfl
      exact ⟨not_dropped, no_records, no_opcode, labels, tail, query, question⟩
    · rintro ⟨_, _, _, labels', tail', query', question'⟩
      obtain ⟨rfl, rfl⟩ := the_reading_is_unique m labels labels' tail tail' query query'
      exact the_question_is_unique q q' m labels tail question question'

end DnsCore
