-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the proofs of the claims of Spec.lean about the answer of `endpoints`: the
-- credentials, the list, the flags, `by_digest`, the refusals and that an answer is not empty.
-- Each is a part of `EndpointsAnswer` (TheAnswerOfEndpoints.lean), read for the block chosen.
-- Why it is needed: Theorems.lean ties each claim of Spec.lean to a proof, and these are the
-- proofs.
-- Read before this file: Spec.lean, TheAnswerOfEndpoints.lean, FactsOfPairedLists.lean.
-- Notation: `WP.spec_mono h ?_` is "use the result `h` about the function, and show that what it
-- says is enough"; `rcases answer with ...` takes the cases of `EndpointsAnswer` apart.
import EndpointCore.Spec
import EndpointCore.TheAnswerOfEndpoints
import EndpointCore.FactsOfPairedLists

open Aeneas Aeneas.Std Result velarx_endpoint_core

namespace EndpointCore

open Classical

theorem command_line_credentials_are_for_the_host_named :
    CommandLineCredentialsAreForTheHostNamed := by
  intro blocks host path ask fits
  obtain ⟨found, chosen⟩ := a_choice_exists blocks host path fits
  refine WP.spec_mono (endpoints_answers blocks host path ask fits found chosen) ?_
  intro r answer es is_ok e e_in
  rcases answer with ⟨_, is_err⟩ | ⟨_, _, is_err⟩ | ⟨_, _, _, is_err⟩ |
    ⟨_, _, _, es', mirrors, primary, is_ok', es_is, _, _, _, primary_creds, _, listed⟩
  · rw [is_ok] at is_err
    cases is_err
  · rw [is_ok] at is_err
    cases is_err
  · rw [is_ok] at is_err
    cases is_err
  · rw [is_ok] at is_ok'
    cases is_ok'
    rw [es_is] at e_in
    rcases List.mem_append.mp e_in with in_mirrors | is_primary
    · obtain ⟨p, _, _, _, _, _, creds, _⟩ := every_element_has_a_partner _ _ _ listed e in_mirrors
      exact creds
    · rw [List.mem_singleton.mp is_primary]
      exact primary_creds

theorem the_list_is_the_listed_mirrors_then_the_registry :
    TheListIsTheListedMirrorsThenTheRegistry := by
  intro blocks host path ask fits found chosen
  refine WP.spec_mono (endpoints_answers blocks host path ask fits found chosen) ?_
  intro r answer es is_ok
  rcases answer with ⟨_, is_err⟩ | ⟨_, _, is_err⟩ | ⟨_, _, _, is_err⟩ |
    ⟨_, _, _, es', mirrors, primary, is_ok', es_is, located, _, _, _, _, listed⟩
  · rw [is_ok] at is_err
    cases is_err
  · rw [is_ok] at is_err
    cases is_err
  · rw [is_ok] at is_err
    cases is_err
  · rw [is_ok] at is_ok'
    cases is_ok'
    refine ⟨mirrors, primary, es_is, located, ?_⟩
    exact List.Forall₂.imp (fun p e is_end => is_end.2.1) listed

theorem flags_are_their_own : FlagsAreTheirOwn := by
  intro blocks host path ask fits found chosen
  refine WP.spec_mono (endpoints_answers blocks host path ask fits found chosen) ?_
  intro r answer es is_ok
  rcases answer with ⟨_, is_err⟩ | ⟨_, _, is_err⟩ | ⟨_, _, _, is_err⟩ |
    ⟨_, _, _, es', mirrors, primary, is_ok', es_is, _, insecure, reaches, _, _, listed⟩
  · rw [is_ok] at is_err
    cases is_err
  · rw [is_ok] at is_err
    cases is_err
  · rw [is_ok] at is_err
    cases is_err
  · rw [is_ok] at is_ok'
    cases is_ok'
    refine ⟨mirrors, primary, es_is, insecure, reaches, ?_⟩
    exact List.Forall₂.imp (fun p e is_end => ⟨is_end.2.2.1, is_end.2.2.2.1⟩) listed

theorem by_digest_is_for_a_digest_mirror : ByDigestIsForADigestMirror := by
  intro blocks host path ask fits found chosen
  refine WP.spec_mono (endpoints_answers blocks host path ask fits found chosen) ?_
  intro r answer es is_ok
  rcases answer with ⟨_, is_err⟩ | ⟨_, _, is_err⟩ | ⟨_, _, _, is_err⟩ |
    ⟨_, _, _, es', mirrors, primary, is_ok', es_is, _, _, _, _, primary_digest, listed⟩
  · rw [is_ok] at is_err
    cases is_err
  · rw [is_ok] at is_err
    cases is_err
  · rw [is_ok] at is_err
    cases is_err
  · rw [is_ok] at is_ok'
    cases is_ok'
    have in_mirrors : ∀ e ∈ mirrors, e.by_digest = true → ask.has_digest = true := by
      intro e e_in digest
      obtain ⟨p, p_in, _, _, _, _, _, digest_says⟩ :=
        every_element_has_a_partner _ _ _ listed e e_in
      have digest_mirror := digest_says.mp digest
      have serves : Serves p.1.mode ask.has_digest := by
        unfold ListedMirrors at p_in
        cases is_chosen : ChosenBlock blocks.val found with
        | none => simp [is_chosen] at p_in
        | some block =>
          simp only [is_chosen] at p_in
          exact a_listed_mirror_serves _ _ _ _ _ _ _ p_in
      rw [digest_mirror] at serves
      exact serves
    refine ⟨?_, mirrors, primary, es_is, primary_digest, ?_⟩
    · intro e e_in digest
      rw [es_is] at e_in
      rcases List.mem_append.mp e_in with from_mirrors | is_primary
      · exact in_mirrors e from_mirrors digest
      · rw [List.mem_singleton.mp is_primary, primary_digest] at digest
        cases digest
    · exact List.Forall₂.imp (fun p e is_end => is_end.2.2.2.2.2) listed

theorem blocked_is_refused_exactly : BlockedIsRefusedExactly := by
  intro blocks host path ask fits found chosen
  refine WP.spec_mono (endpoints_answers blocks host path ask fits found chosen) ?_
  intro r answer
  rcases answer with ⟨blocked, is_err⟩ | ⟨not_blocked, _, is_err⟩ |
    ⟨not_blocked, _, _, is_err⟩ | ⟨not_blocked, _, _, es, _, _, is_ok, _⟩
  · exact ⟨fun _ => blocked, fun _ => is_err⟩
  · constructor
    · intro same
      rw [is_err] at same
      cases same
    · intro blocked
      exact absurd blocked not_blocked
  · constructor
    · intro same
      rw [is_err] at same
      cases same
    · intro blocked
      exact absurd blocked not_blocked
  · constructor
    · intro same
      rw [is_ok] at same
      cases same
    · intro blocked
      exact absurd blocked not_blocked

theorem no_repository_is_refused_exactly : NoRepositoryIsRefusedExactly := by
  intro blocks host path ask fits found chosen
  refine WP.spec_mono (endpoints_answers blocks host path ask fits found chosen) ?_
  intro r answer
  rcases answer with ⟨blocked, is_err⟩ | ⟨not_blocked, no_slash, is_err⟩ |
    ⟨not_blocked, _, mirror, is_err⟩ | ⟨not_blocked, slash, no_mirror, es, _, _, is_ok, _⟩
  · constructor
    · intro same
      rw [is_err] at same
      cases same
    · rintro ⟨not_blocked, _⟩
      exact absurd blocked not_blocked
  · exact ⟨fun _ => ⟨not_blocked, Or.inl no_slash⟩, fun _ => is_err⟩
  · exact ⟨fun _ => ⟨not_blocked, Or.inr mirror⟩, fun _ => is_err⟩
  · constructor
    · intro same
      rw [is_ok] at same
      cases same
    · rintro ⟨_, no_slash | mirror⟩
      · exact absurd slash no_slash
      · exact absurd mirror no_mirror

theorem otherwise_a_list_is_answered : OtherwiseAListIsAnswered := by
  intro blocks host path ask fits found chosen
  refine WP.spec_mono (endpoints_answers blocks host path ask fits found chosen) ?_
  intro r answer
  rcases answer with ⟨blocked, is_err⟩ | ⟨not_blocked, no_slash, is_err⟩ |
    ⟨not_blocked, slash, mirror, is_err⟩ | ⟨not_blocked, slash, no_mirror, es, _, _, is_ok, _⟩
  · constructor
    · rintro ⟨es, same⟩
      rw [is_err] at same
      cases same
    · rintro ⟨not_blocked, _⟩
      exact absurd blocked not_blocked
  · constructor
    · rintro ⟨es, same⟩
      rw [is_err] at same
      cases same
    · rintro ⟨_, slash, _⟩
      exact absurd slash no_slash
  · constructor
    · rintro ⟨es, same⟩
      rw [is_err] at same
      cases same
    · rintro ⟨_, _, no_mirror⟩
      exact absurd mirror no_mirror
  · exact ⟨fun _ => ⟨not_blocked, slash, no_mirror⟩, fun _ => ⟨es, is_ok⟩⟩

theorem an_answer_is_never_empty : AnAnswerIsNeverEmpty := by
  intro blocks host path ask fits
  obtain ⟨found, chosen⟩ := a_choice_exists blocks host path fits
  refine WP.spec_mono (endpoints_answers blocks host path ask fits found chosen) ?_
  intro r answer es is_ok
  rcases answer with ⟨_, is_err⟩ | ⟨_, _, is_err⟩ | ⟨_, _, _, is_err⟩ |
    ⟨_, _, _, es', mirrors, primary, is_ok', es_is, _⟩
  · rw [is_ok] at is_err
    cases is_err
  · rw [is_ok] at is_err
    cases is_err
  · rw [is_ok] at is_err
    cases is_err
  · rw [is_ok] at is_ok'
    cases is_ok'
    rw [es_is]
    simp

end EndpointCore
