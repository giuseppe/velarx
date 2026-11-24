-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: two facts about the name after the defaults of docker.io
-- (`Reference.Normal` of Spec.lean): adding the defaults to it changes nothing, and it is a
-- reference of the grammar when the reference it is made from is.
-- Why it is needed: `normalize` makes that name and `print` writes it; these are what lets the
-- written name be read again, and read as the same name.
-- Read before this file: Spec.lean, ParseComplete.lean.
-- Notation: `r.Normal` is the reference after the defaults; `Path (c ++ 47 :: p)` is a path made
-- of a component, a `/` and a path.
import RefCore.ParseComplete
open Aeneas Aeneas.Std Result velarx_ref_core
namespace RefCore

open Classical in
/-- Adding the defaults of docker.io to a name that has them changes nothing. -/
theorem normal_is_fixed (r : Reference) : r.Normal.Normal = r.Normal := by
  have host_def : r.Normal.host = if r.OnTheHub then some Hub else r.host := rfl
  have path_def : r.Normal.path = (if r.OnTheHub ∧ r.OneComponent then Ascii "library/" else []) ++
      r.path := rfl
  have hub_stays : r.OnTheHub → r.Normal.OnTheHub := by
    intro hub
    unfold Reference.OnTheHub
    rw [host_def]
    simp only [hub, ↓reduceIte, true_or, or_true]
  have off_stays : ¬ r.OnTheHub → ¬ r.Normal.OnTheHub := by
    intro off
    have off0 := off
    unfold Reference.OnTheHub at off ⊢
    rw [host_def]
    simpa only [off0, ↓reduceIte] using off
  apply reference_ext
  · show (if r.Normal.OnTheHub then some Hub else r.Normal.host) = r.Normal.host
    by_cases hub : r.OnTheHub
    · simp only [hub_stays hub, hub, host_def, ↓reduceIte]
    · simp only [off_stays hub, ↓reduceIte]
  · show (if r.Normal.OnTheHub ∧ r.Normal.OneComponent then Ascii "library/" else []) ++
      r.Normal.path = r.Normal.path
    by_cases hub : r.OnTheHub
    · by_cases one : r.OneComponent
      · have not_one : ¬ r.Normal.OneComponent := by
          unfold Reference.OneComponent
          rw [path_def]
          simp only [hub, one, and_self, ↓reduceIte, List.mem_append]
          intro h
          apply h
          simp [Ascii]
        simp only [not_one, and_false, ↓reduceIte, List.nil_append]
      · have one' : ¬ r.OneComponent := one
        have not_one : ¬ r.Normal.OneComponent := by
          show ¬ 47 ∉ r.Normal.path
          rw [path_def]
          simp only [hub, one', and_false, ↓reduceIte, List.nil_append]
          exact one
        simp only [not_one, and_false, ↓reduceIte, List.nil_append]
    · simp only [off_stays hub, false_and, ↓reduceIte, List.nil_append]
  · rfl
  · rfl
/-- `docker.io` is a host of the grammar, and looks like one. -/
theorem hub_is_a_host : IsHost Hub ∧ LooksLikeHost Hub := by
  refine ⟨Or.inr (Or.inl ?_), Or.inl (by simp [Hub, Ascii])⟩
  have cut : Hub = Ascii "docker" ++ [46] ++ Ascii "io" := by decide
  rw [cut]
  have letters : ∀ (text : String), (∀ b ∈ Ascii text, 97 ≤ b ∧ b ≤ 122) →
      ∀ b ∈ Ascii text, IsAlnum b ∨ b = 45 := fun _ all b inside => Or.inl (Or.inl (all b inside))
  refine Domain.join (Domain.label ⟨letters "docker" ?_, ⟨100, rfl, Or.inl ?_⟩,
    ⟨114, rfl, Or.inl ?_⟩⟩) ⟨letters "io" ?_, ⟨105, rfl, Or.inl ?_⟩, ⟨111, rfl, Or.inl ?_⟩⟩
  · intro b inside; simp [Ascii] at inside; omega
  · unfold IsLower; omega
  · unfold IsLower; omega
  · intro b inside; simp [Ascii] at inside; omega
  · unfold IsLower; omega
  · unfold IsLower; omega

/-- A path, a `/` and what can be read as a path, make a path. -/
theorem path_then_a_path {before rest : List Nat} (is_path : Path before)
    (readable : PathRest rest) : Path (before ++ 47 :: rest) := by
  induction readable generalizing before with
  | last is_component => simpa using Path.more is_path is_component
  | step is_component more ih =>
    have := ih (by simpa using Path.more is_path is_component)
    simpa [List.append_assoc] using this

/-- `library/` and a path make a path: `library` is a component. -/
theorem library_then_a_path {p : List Nat} (is_path : Path p) :
    Path (Ascii "library/" ++ p) := by
  have library : Component (Ascii "library") := Component.word ⟨by simp [Ascii], by
    intro b inside; simp [Ascii] at inside
    unfold IsAlnum IsLower IsDigit; omega⟩
  have := path_then_a_path (Path.one library) (path_is_what_can_be_read is_path)
  simpa [Ascii] using this

open Classical in
/-- The name after the defaults of docker.io always has a host. -/
theorem normal_has_a_host (r : Reference) : r.Normal.host ≠ none := by
  have host_def : r.Normal.host = if r.OnTheHub then some Hub else r.host := rfl
  rw [host_def]
  by_cases hub : r.OnTheHub
  · simp [hub]
  · intro is_none
    apply hub
    simp only [hub, ↓reduceIte] at is_none
    exact Or.inl is_none

open Classical in
/-- The name after the defaults of docker.io of a reference of the grammar is a reference of the
grammar. -/
theorem normal_is_in_the_grammar {r : Reference} (grammar : r.InGrammar) :
    r.Normal.InGrammar := by
  have host_def : r.Normal.host = if r.OnTheHub then some Hub else r.host := rfl
  have path_def : r.Normal.path = (if r.OnTheHub ∧ r.OneComponent then Ascii "library/" else []) ++
      r.path := rfl
  have has_host := normal_has_a_host r
  have fixed := normal_is_fixed r
  have same_name : r.Normal.NameLength = r.NameLength := by
    unfold Reference.NameLength
    rw [fixed]
  refine ⟨?_, ?_, fun no_host => absurd no_host has_host, grammar.tag, grammar.digest, ?_, ?_, ?_⟩
  · intro h is_h
    rw [host_def] at is_h
    by_cases hub : r.OnTheHub
    · simp only [hub, ↓reduceIte, Option.some.injEq] at is_h
      rw [← is_h]
      exact hub_is_a_host
    · simp only [hub, ↓reduceIte] at is_h
      exact grammar.host h is_h
  · rw [path_def]
    by_cases both : r.OnTheHub ∧ r.OneComponent
    · simp only [both, and_self, ↓reduceIte]
      exact library_then_a_path grammar.path
    · simp only [both, ↓reduceIte, List.nil_append]
      exact grammar.path
  · obtain ⟨h', is_h'⟩ := Option.ne_none_iff_exists'.mp has_host
    have name_len : r.Normal.NameLength = h'.length + 1 + r.Normal.path.length := by
      unfold Reference.NameLength
      rw [fixed, is_h']
      rfl
    have name_short : r.Normal.NameLength ≤ 255 := by rw [same_name]; exact grammar.name_short
    have tag_long : ((r.Normal.tag.map (58 :: ·)).getD []).length ≤ 129 := by
      cases is_tag : r.Normal.tag with
      | none => simp
      | some t =>
        have := (grammar.tag t is_tag).2.1
        simp only [Option.map_some, Option.getD_some, List.length_cons]
        omega
    have digest_long : ((r.Normal.digest.map (64 :: ·)).getD []).length ≤ 136 := by
      cases is_digest : r.Normal.digest with
      | none => simp
      | some d =>
        obtain ⟨algorithm, count, hex, split, _, hex_count, kinds⟩ := grammar.digest d is_digest
        have seven : (Ascii algorithm).length = 7 := by
          rcases kinds with ⟨rfl, _⟩ | ⟨rfl, _⟩ | ⟨rfl, _⟩ <;> rfl
        have : count ≤ 128 := by rcases kinds with ⟨_, c⟩ | ⟨_, c⟩ | ⟨_, c⟩ <;> omega
        simp only [Option.map_some, Option.getD_some, List.length_cons, split, List.length_append,
          seven, hex_count]
        omega
    unfold Reference.Text
    rw [is_h']
    simp only [Option.map_some, Option.getD_some, List.length_append, List.length_singleton]
    omega
  · rw [same_name]; exact grammar.name_short
  · rintro ⟨no_host, _⟩
    exact has_host no_host

end RefCore
