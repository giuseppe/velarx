-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: how much `answer` asks for when it says `need`: more than the bytes
-- held, no more than any head the bytes can be the beginning of takes, and no more than
-- `4 + 65 * max`; and that no head is longer than that.
-- Why it is needed: the shell reads as many bytes as `Need` asks for; these are the claims that
-- keep it from waiting for bytes that no head needs, or for more than a peer can be made to send.
-- Read before this file: Spec.lean, WhatTheAnswerSays.lean.
-- Notation: `l <+: l'` is "l is the beginning of l'"; `rcases h with ⟨a, b⟩` takes `h` apart.
import RequestCore.WhatTheAnswerSays

open Aeneas Aeneas.Std Result velarx_request_core

open Classical

namespace RequestCore

noncomputable section

/-- **No head is longer than `4 + 65 * max`**: the four bytes, at most `max` algorithm bytes and at
most 64 bytes for each digest. -/
theorem a_head_is_at_most_as_long_as_most (max : Nat) (head : List Std.U8) (count : Nat)
    (is_head : IsAHead max head count) : head.length ≤ 4 + 65 * max := by
  obtain ⟨operation, urgency, high, low, algorithms, raw, is_head, _, _, at_most, count_algorithms,
    _, raw_length⟩ := is_head
  have := digests_take_at_most_64_each algorithms
  rw [is_head]
  simp only [List.length_cons, List.length_append]
  omega

/-- What a head that the bytes begin has in common with them: when `bytes` is the beginning of a
head, the head has the same four first bytes, so the same count. -/
theorem a_head_that_bytes_begin (max : Nat) (operation urgency high low : Std.U8)
    (tail : List Std.U8) (head : List Std.U8) (count : Nat)
    (is_head : IsAHead max head count)
    (begins : (operation :: urgency :: high :: low :: tail) <+: head) :
    ∃ algorithms raw, head = operation :: urgency :: high :: low :: (algorithms ++ raw) ∧
      count = high.val * 256 + low.val ∧ algorithms.length = count ∧
      raw.length = (algorithms.map AlgorithmLength).sum ∧ tail <+: algorithms ++ raw := by
  obtain ⟨operation', urgency', high', low', algorithms, raw, is_head, is_count, _, _,
    count_algorithms, _, raw_length⟩ := is_head
  obtain ⟨extra, extends_to⟩ := begins
  rw [is_head] at extends_to
  simp only [List.cons_append, List.cons.injEq] at extends_to
  obtain ⟨rfl, rfl, rfl, rfl, is_tail⟩ := extends_to
  exact ⟨algorithms, raw, is_head, is_count, count_algorithms, raw_length, extra, is_tail⟩

/-- **What `need` asks for.**  When `answer` says `need n`: `n` is more than the bytes held, at most
what any head the bytes are the beginning of takes, and at most `4 + 65 * max`. -/
theorem need_answer_asks_for_what_a_head_takes (bytes : List Std.U8) (max n : Nat)
    (is_need : answer bytes max = .need n) :
    bytes.length < n ∧
      (∀ head count, IsAHead max head count → bytes <+: head → n ≤ head.length) ∧
      n ≤ 4 + 65 * max := by
  by_cases short : bytes.length < 4
  · rw [(short_bytes bytes max short).1] at is_need
    injection is_need with is_n
    subst is_n
    refine ⟨short, ?_, by omega⟩
    intro head count is_head _
    obtain ⟨_, _, _, _, algorithms, raw, is_head, _⟩ := is_head
    rw [is_head]
    simp
  · rcases bytes with _ | ⟨operation, _ | ⟨urgency, _ | ⟨high, _ | ⟨low, tail⟩⟩⟩⟩
    all_goals try (simp only [List.length_cons, List.length_nil] at short; omega)
    simp only [answer, List.length_cons] at is_need
    generalize is_c : high.val * 256 + low.val = c at is_need
    split_ifs at is_need
    · -- some algorithm bytes are missing
      rename_i valid known missing
      injection is_need with is_n
      subst is_n
      refine ⟨by simp only [List.length_cons]; omega, ?_, by omega⟩
      intro head count is_head begins
      obtain ⟨algorithms, raw, is_head', is_count, count_algorithms, _⟩ :=
        a_head_that_bytes_begin max operation urgency high low tail head count is_head begins
      rw [is_head']
      simp only [List.length_cons, List.length_append]
      omega
    · -- the digests are not all there
      rename_i valid known there waiting
      injection is_need with is_n
      subst is_n
      refine ⟨by simp only [List.length_cons]; omega, ?_, ?_⟩
      · intro head count is_head begins
        obtain ⟨algorithms, raw, is_head', is_count, count_algorithms, raw_length, prefix_of⟩ :=
          a_head_that_bytes_begin max operation urgency high low tail head count is_head begins
        obtain ⟨extra, is_tail⟩ := prefix_of
        have same_algorithms : tail.take c = algorithms := by
          calc tail.take c = (tail ++ extra).take c :=
                (List.take_append_of_le_length (by omega)).symm
            _ = (algorithms ++ raw).take c := by rw [is_tail]
            _ = algorithms := by
                rw [show c = algorithms.length by omega]
                exact List.take_left
        rw [is_head']
        simp only [List.length_cons, List.length_append]
        rw [same_algorithms]
        omega
      · have := digests_take_at_most_64_each (tail.take c)
        have : (tail.take c).length ≤ c := List.length_take_le _ _
        omega

end

end RequestCore
