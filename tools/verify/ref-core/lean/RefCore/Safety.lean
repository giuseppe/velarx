-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what the bytes of a host and of a path of the grammar can be: no `/`, `@`,
-- `?`, `#`, `%`, no capital, no white space, no control byte; and that a path is components, none
-- of them empty, `.` or `..`.
-- Why it is needed: these are what keeps a reference from reaching a URL as something else.
-- Read before this file: Spec.lean.
-- Notation: `JoinedBySlashes comps` is the components written with a `/` between two.
import RefCore.Spec
namespace RefCore

/-- The bytes of a domain name are lower-case letters, digits, `-` and `.`. -/
theorem domain_bytes {d : List Nat} (is_domain : Domain d) :
    ∀ b ∈ d, IsAlnum b ∨ b = 45 ∨ b = 46 := by
  induction is_domain with
  | label is_label =>
    intro b inside
    rcases is_label.1 b inside with alnum | hyphen
    · exact Or.inl alnum
    · exact Or.inr (Or.inl hyphen)
  | join old is_label ih =>
    intro b inside
    simp only [List.mem_append, List.mem_singleton] at inside
    rcases inside with (before | dot) | label
    · exact ih b before
    · exact Or.inr (Or.inr dot)
    · rcases is_label.1 b label with alnum | hyphen
      · exact Or.inl alnum
      · exact Or.inr (Or.inl hyphen)

/-- The bytes of a host are lower-case letters, digits, `-`, `.`, `:`, `[` and `]`. -/
theorem host_bytes {h : List Nat} (is_host : IsHost h) :
    ∀ b ∈ h, IsAlnum b ∨ b = 45 ∨ b = 46 ∨ b = 58 ∨ b = 91 ∨ b = 93 := by
  intro b inside
  rcases is_host with ⟨inner, rest, split, _, inner_ok, rest_ok⟩ | domain |
      ⟨d, p, is_d, is_p, split⟩
  · rw [split] at inside
    simp only [List.mem_append, List.mem_singleton] at inside
    rcases inside with ((open_ | in_inner) | close) | in_rest
    · exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inl open_))))
    · rcases inner_ok b in_inner with hex | colon
      · refine Or.inl ?_
        rcases hex with digit | letter
        · exact Or.inr digit
        · exact Or.inl ⟨letter.1, by omega⟩
      · exact Or.inr (Or.inr (Or.inr (Or.inl colon)))
    · exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inr close))))
    · rcases rest_ok with empty | ⟨port, rest_is, is_port⟩
      · rw [empty] at in_rest; simp at in_rest
      · rw [rest_is] at in_rest
        rcases List.mem_cons.mp in_rest with colon | in_port
        · exact Or.inr (Or.inr (Or.inr (Or.inl colon)))
        · exact Or.inl (Or.inr (is_port.2 b in_port))
  · rcases domain_bytes domain b inside with a | h | d
    · exact Or.inl a
    · exact Or.inr (Or.inl h)
    · exact Or.inr (Or.inr (Or.inl d))
  · rw [split] at inside
    simp only [List.mem_append, List.mem_singleton] at inside
    rcases inside with (in_d | colon) | in_p
    · rcases domain_bytes is_d b in_d with a | h | d
      · exact Or.inl a
      · exact Or.inr (Or.inl h)
      · exact Or.inr (Or.inr (Or.inl d))
    · exact Or.inr (Or.inr (Or.inr (Or.inl colon)))
    · exact Or.inl (Or.inr (is_p.2 b in_p))

/-- A component begins with a letter or a digit and its bytes are letters, digits, `.`, `_`, `-`. -/
theorem component_shape {c : List Nat} (is_component : Component c) :
    (∃ x rest, c = x :: rest ∧ IsAlnum x) ∧ ∀ b ∈ c, IsAlnum b ∨ b = 46 ∨ b = 95 ∨ b = 45 := by
  induction is_component with
  | @word w is_word =>
    refine ⟨?_, fun b inside => Or.inl (is_word.2 b inside)⟩
    cases w with
    | nil => exact absurd rfl is_word.1
    | cons x rest => exact ⟨x, rest, rfl, is_word.2 x (by simp)⟩
  | @join c sep w old sep_ok word ih =>
    obtain ⟨⟨x, rest, c_is, x_alnum⟩, bytes⟩ := ih
    refine ⟨⟨x, rest ++ sep ++ w, by rw [c_is]; simp, x_alnum⟩, fun b inside => ?_⟩
    simp only [List.mem_append] at inside
    rcases inside with (old_byte | sep_byte) | word_byte
    · exact bytes b old_byte
    · rcases sep_ok with dot | under | under2 | ⟨_, hyphens⟩
      · rw [dot] at sep_byte; simp at sep_byte; exact Or.inr (Or.inl sep_byte)
      · rw [under] at sep_byte; simp at sep_byte; exact Or.inr (Or.inr (Or.inl sep_byte))
      · rw [under2] at sep_byte; simp at sep_byte
        exact Or.inr (Or.inr (Or.inl sep_byte))
      · exact Or.inr (Or.inr (Or.inr (hyphens b sep_byte)))
    · exact Or.inl (word.2 b word_byte)

/-- One more component after the others, with a `/`. -/
theorem join_one_more (comps : List (List Nat)) (c : List Nat) (not_empty : comps ≠ []) :
    JoinedBySlashes (comps ++ [c]) = JoinedBySlashes comps ++ [47] ++ c := by
  induction comps with
  | nil => exact absurd rfl not_empty
  | cons first rest ih =>
    cases rest with
    | nil => simp [JoinedBySlashes]
    | cons second more =>
      have := ih (by simp)
      simp only [List.cons_append, JoinedBySlashes] at this ⊢
      rw [this]
      simp

/-- A path is its components, each joined to the next by a `/`. -/
theorem path_is_its_components {p : List Nat} (is_path : Path p) :
    ∃ comps, comps ≠ [] ∧ (∀ c ∈ comps, Component c) ∧ p = JoinedBySlashes comps := by
  induction is_path with
  | @one c is_component => exact ⟨[c], by simp, by simpa using is_component,
      by simp [JoinedBySlashes]⟩
  | @more p c old is_component ih =>
    obtain ⟨comps, not_empty, all, eq⟩ := ih
    refine ⟨comps ++ [c], by simp, ?_, ?_⟩
    · intro c inside
      rcases List.mem_append.mp inside with before | now
      · exact all c before
      · rw [List.mem_singleton.mp now]; exact is_component
    · rw [join_one_more comps c not_empty, eq]

/-- A host of the grammar has none of the dangerous bytes. -/
theorem host_is_safe {h : List Nat} (is_host : IsHost h) : HostIsSafe h := by
  intro b inside danger
  have bytes := host_bytes is_host b inside
  unfold Dangerous IsUpper at danger
  unfold IsAlnum IsLower IsDigit at bytes
  omega

end RefCore
