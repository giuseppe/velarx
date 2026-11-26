-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the claims of Spec.lean that are not a single function's answer, from the
-- answers of the functions: that each function returns, that a key that matches starts with the host,
-- that the three names of the Hub are one host (`matches`, `pick` and `exact` answer the same), and
-- that a name of the Hub with a port is not the Hub; and `AWebKeyIsItsHost` from `normalize`.
-- Why it is needed: these are what a reader of the Rust wants to know of the crate.
-- Read before this file: Spec.lean, TheMatch.lean, ThePick.lean, TheExact.lean, TheNormalize.lean.
-- Notation: `f x ⦃ r => P r ⦄` reads: `f` returns a value `r` of which `P` holds; `l.takeWhile p` is
-- what is before the first element that does not satisfy `p`.
import AuthCore.Spec
import AuthCore.TheHub
import AuthCore.TheMatch
import AuthCore.ThePick
import AuthCore.TheExact
import AuthCore.TheNormalize

open Aeneas Aeneas.Std Aeneas.Data.Coinductive Result velarx_auth_core

namespace AuthCore

unseal Result in
attribute [local implicit_reducible] Result in
/-- A call that satisfies a claim returns a value (of which the claim holds). -/
theorem spec_returns {α : Type} {m : Result α} {P : α → Prop} (h : m ⦃ y => P y ⦄) :
    ∃ x, m = ok x ∧ P x := by
  cases m using ITree.cases with
  | ret x =>
    change ok x ⦃ y => P y ⦄ at h
    exact ⟨x, rfl, (WP.spec_ok x).mp h⟩
  | vis e k => exact ((WP.spec_vis e k).mp h).elim
  | div => exact (WP.spec_div.mp h).elim

/-- **`EveryFunctionReturns`**: each function of the crate returns for any input. -/
theorem every_function_returns : EveryFunctionReturns := by
  refine ⟨fun key => ?_, fun key host repo => ?_, fun keys host repo => ?_, fun keys host => ?_,
    fun host => ?_⟩
  · obtain ⟨r, e, _⟩ := spec_returns (normalize_is_the_rule key)
    exact ⟨r, e⟩
  · obtain ⟨r, e, _⟩ := spec_returns (matches_says key host repo)
    exact ⟨r, e⟩
  · obtain ⟨r, e, _⟩ := spec_returns (pick_picks keys host repo)
    exact ⟨r, e⟩
  · obtain ⟨r, e, _⟩ := spec_returns (exact_finds_the_host keys host)
    exact ⟨r, e⟩
  · obtain ⟨r, e, _⟩ := spec_returns (hub_alias_is_the_two_names host)
    exact ⟨r, e⟩

theorem matches_is_exactly_the_definition : MatchesIsExactlyTheDefinition :=
  fun key host repo => matches_says key host repo

theorem hub_alias_is_the_two_other_names : HubAliasIsTheTwoOtherNames :=
  fun host => hub_alias_is_the_two_names host

theorem pick_is_the_most_specific_key : PickIsTheMostSpecificKey :=
  fun keys host repo => pick_picks keys host repo

theorem exact_is_the_host_alone : ExactIsTheHostAlone :=
  fun keys host => exact_finds_the_host keys host

theorem normalize_is_the_rule_of_the_key : NormalizeIsTheRuleOfTheKey :=
  fun key => normalize_is_the_rule key

/-- A list with no `/` is its own first component. -/
theorem no_slash_is_one_component (l : Bytes) (none : Slash ∉ l) :
    l.takeWhile (fun b => decide (b ≠ Slash)) = l := by
  induction l with
  | nil => rfl
  | cons c l ih =>
    have c_ne : c ≠ Slash := fun h => none (by simp [h])
    rw [List.takeWhile_cons_of_pos (by simpa using c_ne), ih (fun h => none (by simp [h]))]

/-- The Hub under its one name has no `/`, nor has the host of a request that has none. -/
theorem hub_of_has_no_slash (host : Bytes) (none : Slash ∉ host) : Slash ∉ HubOf host := by
  unfold HubOf
  split
  · decide
  · exact none

/-- **`AKeyIsForItsHostOnly`**: a key that matches starts with the host. -/
theorem a_key_is_for_its_host_only : AKeyIsForItsHostOnly := by
  intro key host repo no_slash
  refine WP.spec_mono (matches_says key host repo) ?_
  intro r h answered
  rcases h with ⟨m, rfl⟩ | ⟨_, rfl⟩
  · have hub := no_slash_is_one_component _ (hub_of_has_no_slash host.val no_slash)
    have p_all : ∀ a ∈ HubOf host.val, decide (a ≠ Slash) = true := by
      intro a ha
      have : a ≠ Slash := fun h => hub_of_has_no_slash host.val no_slash (by subst h; exact ha)
      simpa using this
    rcases m with eq | ⟨path, eq, _⟩
    · rw [eq]; exact hub
    · rw [eq, List.takeWhile_append_of_pos p_all, List.takeWhile_cons_of_neg (by simp)]
      simp
  · exact absurd rfl answered

/-- The three names of the Hub are `docker.io`. -/
theorem hub_names_are_one (a : Bytes) (h : a = HubName ∨ a = HubIndex ∨ a = HubRegistry) :
    HubOf a = HubName := by
  unfold HubOf
  rcases h with rfl | rfl | rfl <;> simp

/-- Two picks for the same keys are the same when the same keys match. -/
theorem picks_are_unique (keys : List Key) (host host' repo : Bytes)
    (same : ∀ k, Matches k host repo ↔ Matches k host' repo) (f g : Option Nat)
    (hf : Picks keys host repo f) (hg : Picks keys host' repo g) : f = g := by
  obtain ⟨hf1, hf2⟩ := hf
  obtain ⟨hg1, hg2⟩ := hg
  cases f with
  | none =>
    cases g with
    | none => rfl
    | some j =>
      obtain ⟨k, k_at, m, _⟩ := hg1 j rfl
      exact absurd ((same _).mpr m) (hf2.mp rfl k (List.mem_of_getElem? k_at))
  | some i =>
    cases g with
    | none =>
      obtain ⟨k, k_at, m, _⟩ := hf1 i rfl
      exact absurd ((same _).mp m) (hg2.mp rfl k (List.mem_of_getElem? k_at))
    | some j =>
      obtain ⟨ki, ki_at, mi, besti⟩ := hf1 i rfl
      obtain ⟨kj, kj_at, mj, bestj⟩ := hg1 j rfl
      have a := besti j kj kj_at ((same _).mpr mj)
      have b := bestj i ki ki_at ((same _).mp mi)
      unfold NotBeaten at a b
      congr 1
      by_cases wi : AsWritten ki <;> by_cases wj : AsWritten kj <;>
        simp only [wi, wj, true_and, false_and, iff_true, iff_false, not_true,
          not_false_eq_true, and_true, false_or, or_false, and_false, or_self,
          iff_self] at a b <;> omega

/-- The first key that is the host is the same for the same host. -/
theorem finds_are_unique (keys : List Bytes) (host host' : Bytes) (same : HubOf host = HubOf host')
    (f g : Option Nat) (hf : FindsTheHost keys host f) (hg : FindsTheHost keys host' g) : f = g := by
  obtain ⟨hf1, hf2⟩ := hf
  obtain ⟨hg1, hg2⟩ := hg
  rw [← same] at hg1 hg2
  cases f with
  | none =>
    cases g with
    | none => rfl
    | some j =>
      obtain ⟨at_j, _⟩ := hg1 j rfl
      exact absurd rfl (hf2.mp rfl _ (List.mem_of_getElem? at_j))
  | some i =>
    cases g with
    | none =>
      obtain ⟨at_i, _⟩ := hf1 i rfl
      exact absurd rfl (hg2.mp rfl _ (List.mem_of_getElem? at_i))
    | some j =>
      obtain ⟨at_i, before_i⟩ := hf1 i rfl
      obtain ⟨at_j, before_j⟩ := hg1 j rfl
      congr 1
      by_contra differ
      rcases Nat.lt_or_gt_of_ne differ with lt | lt
      · exact before_j i _ lt at_i rfl
      · exact before_i j _ lt at_j rfl

/-- A key that is a scheme without a `:`, then `://` and the rest is cut there. -/
theorem split_at_the_scheme (scheme rest : Bytes) (no_colon : Colon ∉ scheme) :
    SchemeSplit (scheme ++ SchemeEnd ++ rest) = some (scheme, rest) := by
  induction scheme with
  | nil =>
    show SchemeSplit (Colon :: Slash :: Slash :: rest) = some ([], rest)
    have p : SchemeEnd <+: Colon :: Slash :: Slash :: rest := List.prefix_append _ _
    simp [SchemeSplit, p]
  | cons c scheme ih =>
    have c_ne : c ≠ Colon := fun h => no_colon (by simp [h])
    show SchemeSplit (c :: (scheme ++ SchemeEnd ++ rest)) = some (c :: scheme, rest)
    have : ¬ SchemeEnd <+: c :: (scheme ++ SchemeEnd ++ rest) := by
      rintro ⟨t, ht⟩
      simp [SchemeEnd] at ht
      exact c_ne ht.1.symm
    simp only [SchemeSplit, this, ↓reduceIte]
    rw [ih (fun h => no_colon (by simp [h]))]
    simp

/-- A scheme that is `http` or `https` in lower case has no `:`. -/
theorem a_web_scheme_has_no_colon (scheme : Bytes) (web : IsWeb scheme) : Colon ∉ scheme := by
  intro h
  have : LowerByte Colon ∈ scheme.map LowerByte := List.mem_map_of_mem h
  have lower_colon : LowerByte Colon = Colon := by decide
  rw [lower_colon] at this
  rcases web with e | e <;> rw [e] at this <;> exact absurd this (by decide)

/-- **`AWebKeyIsItsHost`**: a web key is its host. -/
theorem a_web_key_is_its_host : AWebKeyIsItsHost := by
  intro key scheme rest web is_key
  refine WP.spec_mono (normalize_is_the_rule key) ?_
  intro out h
  have split : SchemeSplit key.val = some (scheme, rest) := by
    rw [is_key]; exact split_at_the_scheme scheme rest (a_web_scheme_has_no_colon scheme web)
  rw [h, Normalized, split]
  simp only [web, ↓reduceIte]

/-- **`TheHubIsOneHost`**: the three names of the Hub give the same answers. -/
theorem the_hub_is_one_host : TheHubIsOneHost := by
  intro a b ha hb
  have same : HubOf a.val = HubOf b.val := by rw [hub_names_are_one _ ha, hub_names_are_one _ hb]
  have same_matches : ∀ k repo, Matches k a.val repo ↔ Matches k b.val repo := by
    intro k repo; simp only [Matches, same]
  refine ⟨fun key repo => ?_, fun keys repo => ?_, fun keys => ?_⟩
  · obtain ⟨r1, e1, p1⟩ := spec_returns (matches_says key a repo)
    obtain ⟨r2, e2, p2⟩ := spec_returns (matches_says key b repo)
    rw [e1, e2]
    congr 1
    have := same_matches key.val repo.val
    rcases p1 with ⟨m1, rfl⟩ | ⟨m1, rfl⟩ <;> rcases p2 with ⟨m2, rfl⟩ | ⟨m2, rfl⟩
    · rfl
    · exact absurd (this.mp m1) m2
    · exact absurd (this.mpr m2) m1
    · rfl
  · obtain ⟨r1, e1, p1⟩ := spec_returns (pick_picks keys a repo)
    obtain ⟨r2, e2, p2⟩ := spec_returns (pick_picks keys b repo)
    rw [e1, e2]
    congr 1
    have := picks_are_unique keys.val a.val b.val repo.val (fun k => same_matches k _) _ _ p1 p2
    cases r1 with
    | none => cases r2 with
      | none => rfl
      | some j => simp at this
    | some i => cases r2 with
      | none => simp at this
      | some j =>
        simp only [Option.map_some, Option.some.injEq] at this
        rw [UScalar.eq_of_val_eq this]
  · obtain ⟨r1, e1, p1⟩ := spec_returns (exact_finds_the_host keys a)
    obtain ⟨r2, e2, p2⟩ := spec_returns (exact_finds_the_host keys b)
    rw [e1, e2]
    congr 1
    have := finds_are_unique _ a.val b.val same _ _ p1 p2
    cases r1 with
    | none => cases r2 with
      | none => rfl
      | some j => simp at this
    | some i => cases r2 with
      | none => simp at this
      | some j =>
        simp only [Option.map_some, Option.some.injEq] at this
        rw [UScalar.eq_of_val_eq this]

/-- **`AHubNameWithAPortIsNotTheHub`**: no key of the Hub is for `name:port`. -/
theorem a_hub_name_with_a_port_is_not_the_hub : AHubNameWithAPortIsNotTheHub := by
  intro hub port host key repo hub_name is_host key_name
  refine WP.spec_mono (matches_says key host repo) ?_
  intro r h
  rcases h with ⟨m, rfl⟩ | ⟨_, rfl⟩
  · exfalso
    have no_colon : Colon ∉ key.val := by
      rcases key_name with h | h | h <;> rw [h] <;> decide
    have colon_in : Colon ∈ host.val := by rw [is_host]; simp
    have not_alias : ¬ (host.val = HubIndex ∨ host.val = HubRegistry) := by
      rintro (h | h) <;> rw [h] at colon_in <;> exact absurd colon_in (by decide)
    have host_hub : HubOf host.val = host.val := by simp [HubOf, not_alias]
    have colon_in_host : Colon ∈ HubOf host.val := by rw [host_hub]; exact colon_in
    rcases m with eq | ⟨path, eq, _⟩
    · exact no_colon (eq ▸ colon_in_host)
    · exact no_colon (by rw [eq]; simp [colon_in_host])
  · rfl

end AuthCore
