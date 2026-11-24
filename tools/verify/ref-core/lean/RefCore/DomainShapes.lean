-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: how a domain name is made, read from left to right: what its beginning can
-- be (`DomainSoFar`: nothing, a whole name, a name and hyphens, a name and a dot) and what one
-- more byte makes of it. It also shows what the beginning of a domain name can be when a byte is
-- taken off its end.
-- Why it is needed: `domain_bad` reads a host a byte at a time and looks at the byte before; this
-- is the proof that doing so reads exactly the domain names of Spec.lean (`Domain`).
-- Read before this file: Spec.lean (`Domain`, `IsLabel`), Pieces.lean.
-- Notation: `l.replicate`-style `List.replicate n 45` is `n` hyphens (45 is the number of `-`).
import RefCore.Pieces
namespace RefCore

/-- A letter or a digit is a label. -/
theorem label_single {b : Nat} (alnum : IsAlnum b) : IsLabel [b] :=
  ⟨fun x inside => by rw [List.mem_singleton.mp inside]; exact Or.inl alnum,
    ⟨b, rfl, alnum⟩, ⟨b, rfl, alnum⟩⟩

/-- A label with one more letter or digit is a label. -/
theorem label_snoc_alnum (label : List Nat) (b : Nat) (is_label : IsLabel label)
    (alnum : IsAlnum b) : IsLabel (label ++ [b]) := by
  obtain ⟨all, ⟨first, first_is, first_alnum⟩, _⟩ := is_label
  refine ⟨?_, ⟨first, ?_, first_alnum⟩, ⟨b, by simp, alnum⟩⟩
  · intro x inside
    rcases List.mem_append.mp inside with old | new
    · exact all x old
    · rw [List.mem_singleton.mp new]; exact Or.inl alnum
  · cases label with
    | nil => simp at first_is
    | cons head rest => simpa using first_is

/-- A label with hyphens and then one more letter or digit is a label. -/
theorem label_snoc_hyphens (label : List Nat) (hyphens : Nat) (b : Nat) (is_label : IsLabel label)
    (alnum : IsAlnum b) : IsLabel (label ++ List.replicate hyphens 45 ++ [b]) := by
  obtain ⟨all, ⟨first, first_is, first_alnum⟩, last⟩ := is_label
  refine ⟨?_, ⟨first, ?_, first_alnum⟩, ⟨b, by simp, alnum⟩⟩
  · intro x inside
    simp only [List.mem_append, List.mem_replicate, List.mem_singleton] at inside
    rcases inside with (old | ⟨_, same⟩) | new
    · exact all x old
    · exact Or.inr same
    · rw [new]; exact Or.inl alnum
  · cases label with
    | nil => simp at first_is
    | cons head rest => simpa using first_is

/-- The last byte of a domain name is a letter or a digit. -/
theorem domain_ends_in_alnum {d : List Nat} (is_domain : Domain d) :
    ∃ z, d.getLast? = some z ∧ IsAlnum z := by
  cases is_domain with
  | label is_label => exact is_label.2.2
  | @join before label _ is_label =>
    obtain ⟨z, z_is, z_alnum⟩ := is_label.2.2
    have filled : label ≠ [] := by rintro rfl; simp at z_is
    exact ⟨z, by rw [List.getLast?_append_of_ne_nil _ filled]; exact z_is, z_alnum⟩

/-- A domain name with one more letter or digit is a domain name. -/
theorem domain_snoc_alnum {d : List Nat} (is_domain : Domain d) {b : Nat} (alnum : IsAlnum b) :
    Domain (d ++ [b]) := by
  cases is_domain with
  | label is_label => exact Domain.label (label_snoc_alnum _ _ is_label alnum)
  | join old is_label =>
    have := Domain.join old (label_snoc_alnum _ _ is_label alnum)
    simpa [List.append_assoc] using this

/-- What the beginning of a domain name can be while it is read from left to right: nothing, a
whole domain name, a domain name and hyphens, or a domain name and a dot. -/
def DomainSoFar (l : List Nat) : Prop :=
  l = [] ∨ Domain l ∨ (∃ d k, Domain d ∧ l = d ++ List.replicate (k + 1) 45) ∨
    ∃ d, Domain d ∧ l = d ++ [46]

/-- A domain name and hyphens, and then a letter or a digit, is a domain name. -/
theorem domain_snoc_hyphens {d : List Nat} (is_domain : Domain d) (hyphens : Nat) {b : Nat}
    (alnum : IsAlnum b) : Domain (d ++ List.replicate hyphens 45 ++ [b]) := by
  cases is_domain with
  | label is_label => exact Domain.label (label_snoc_hyphens _ _ _ is_label alnum)
  | join old is_label =>
    have := Domain.join old (label_snoc_hyphens _ hyphens _ is_label alnum)
    simpa [List.append_assoc] using this

/-- A letter or a digit after the beginning of a domain name makes a domain name. -/
theorem so_far_then_alnum {l : List Nat} (so_far : DomainSoFar l) {b : Nat} (alnum : IsAlnum b) :
    Domain (l ++ [b]) := by
  rcases so_far with empty | whole | ⟨d, k, is_domain, hyphens⟩ | ⟨d, is_domain, dot⟩
  · rw [empty]
    exact Domain.label (label_single alnum)
  · exact domain_snoc_alnum whole alnum
  · rw [hyphens]
    exact domain_snoc_hyphens is_domain _ alnum
  · rw [dot]
    exact Domain.join is_domain (label_single alnum)

/-- The last byte of what a domain name begins with, when it is not empty and not a whole name, is a
hyphen or a dot. -/
theorem so_far_then_hyphen {l : List Nat} (so_far : DomainSoFar l) (filled : l ≠ [])
    (not_dot : l.getLast? ≠ some 46) : DomainSoFar (l ++ [45]) := by
  rcases so_far with empty | whole | ⟨d, k, is_domain, hyphens⟩ | ⟨d, is_domain, dot⟩
  · exact absurd empty filled
  · exact Or.inr (Or.inr (Or.inl ⟨l, 0, whole, by simp⟩))
  · refine Or.inr (Or.inr (Or.inl ⟨d, k + 1, is_domain, ?_⟩))
    rw [hyphens, List.append_assoc, ← List.replicate_succ']
  · exact absurd (by rw [dot]; simp) not_dot

/-- After a whole domain name a dot makes the beginning of a longer one. -/
theorem so_far_then_dot {l : List Nat} (so_far : DomainSoFar l) (filled : l ≠ [])
    (alnum_last : ∃ z, l.getLast? = some z ∧ IsAlnum z) : DomainSoFar (l ++ [46]) := by
  rcases so_far with empty | whole | ⟨d, k, is_domain, hyphens⟩ | ⟨d, is_domain, dot⟩
  · exact absurd empty filled
  · exact Or.inr (Or.inr (Or.inr ⟨l, whole, rfl⟩))
  · obtain ⟨z, z_is, z_alnum⟩ := alnum_last
    rw [hyphens, List.getLast?_append_of_ne_nil _ (by simp)] at z_is
    have : z = 45 := by simp [List.getLast?_replicate] at z_is; omega
    subst this
    unfold IsAlnum IsLower IsDigit at z_alnum
    omega
  · obtain ⟨z, z_is, z_alnum⟩ := alnum_last
    rw [dot] at z_is
    simp at z_is
    subst z_is
    unfold IsAlnum IsLower IsDigit at z_alnum
    omega

/-- The beginning of a domain name that ends in neither a dot nor a hyphen ends in a letter or a
digit. -/
theorem so_far_last_alnum {l : List Nat} (so_far : DomainSoFar l) (filled : l ≠ [])
    (not_dot : l.getLast? ≠ some 46) (not_hyphen : l.getLast? ≠ some 45) :
    ∃ z, l.getLast? = some z ∧ IsAlnum z := by
  rcases so_far with empty | whole | ⟨d, k, is_domain, hyphens⟩ | ⟨d, is_domain, dot⟩
  · exact absurd empty filled
  · exact domain_ends_in_alnum whole
  · refine absurd ?_ not_hyphen
    rw [hyphens, List.getLast?_append_of_ne_nil _ (by simp)]
    simp [List.getLast?_replicate]
  · exact absurd (by rw [dot]; simp) not_dot

/-- The beginning of a domain name that ends in a letter or a digit is a whole domain name. -/
theorem so_far_alnum_last {l : List Nat} (so_far : DomainSoFar l) (filled : l ≠ [])
    (alnum_last : ∃ z, l.getLast? = some z ∧ IsAlnum z) : Domain l := by
  rcases so_far with empty | whole | ⟨d, k, is_domain, hyphens⟩ | ⟨d, is_domain, dot⟩
  · exact absurd empty filled
  · exact whole
  · obtain ⟨z, z_is, z_alnum⟩ := alnum_last
    rw [hyphens, List.getLast?_append_of_ne_nil _ (by simp)] at z_is
    have : z = 45 := by simp [List.getLast?_replicate] at z_is; omega
    subst this
    unfold IsAlnum IsLower IsDigit at z_alnum
    omega
  · obtain ⟨z, z_is, z_alnum⟩ := alnum_last
    rw [dot] at z_is
    simp at z_is
    subst z_is
    unfold IsAlnum IsLower IsDigit at z_alnum
    omega

/-- The bytes of a label with a byte taken off its end: nothing, a label, or a label and hyphens
(the shape of a label read from left to right, up to its last byte). -/
theorem label_so_far (l : List Nat) (all : ∀ b ∈ l, IsAlnum b ∨ b = 45)
    (first : ∀ b, l.head? = some b → IsAlnum b) :
    l = [] ∨ IsLabel l ∨ ∃ d k, IsLabel d ∧ l = d ++ List.replicate (k + 1) 45 := by
  induction l using List.reverseRecOn with
  | nil => exact Or.inl rfl
  | append_singleton before y ih =>
    have all_before : ∀ b ∈ before, IsAlnum b ∨ b = 45 := fun b inside =>
      all b (List.mem_append_left _ inside)
    have y_ok : IsAlnum y ∨ y = 45 := all y (by simp)
    have first_before : ∀ b, before.head? = some b → IsAlnum b := by
      intro b is_head
      apply first b
      cases before with
      | nil => simp at is_head
      | cons head rest => simpa using is_head
    rcases ih all_before first_before with empty | is_label | ⟨d, k, is_d, hyphens⟩
    · subst empty
      rcases y_ok with alnum | hyphen
      · exact Or.inr (Or.inl (by simpa using label_single alnum))
      · exact absurd hyphen (by
          have := first y (by simp)
          unfold IsAlnum IsLower IsDigit at this
          omega)
    · rcases y_ok with alnum | hyphen
      · exact Or.inr (Or.inl (label_snoc_alnum _ _ is_label alnum))
      · exact Or.inr (Or.inr ⟨before, 0, is_label, by simp [hyphen]⟩)
    · rcases y_ok with alnum | hyphen
      · refine Or.inr (Or.inl ?_)
        have := label_snoc_hyphens d (k + 1) y is_d alnum
        rwa [← hyphens] at this
      · refine Or.inr (Or.inr ⟨d, k + 1, is_d, ?_⟩)
        rw [hyphens, hyphen, List.append_assoc, ← List.replicate_succ']

/-- A domain name is a label, or a domain name, a dot and a label. -/
theorem domain_cases {w : List Nat} (is_domain : Domain w) :
    IsLabel w ∨ ∃ d lab, Domain d ∧ IsLabel lab ∧ w = d ++ [46] ++ lab := by
  cases is_domain with
  | label is_label => exact Or.inl is_label
  | join old is_label => exact Or.inr ⟨_, _, old, is_label, rfl⟩

/-- A whole domain name, with its last byte taken off, still begins a domain name. -/
theorem domain_so_far_before_the_last_byte {l : List Nat} {x : Nat}
    (is_domain : Domain (l ++ [x])) : DomainSoFar l := by
  have x_alnum : IsAlnum x := by
    obtain ⟨z, z_is, z_alnum⟩ := domain_ends_in_alnum is_domain
    rw [List.getLast?_append_of_ne_nil] at z_is
    · simp at z_is
      rw [z_is]; exact z_alnum
    · simp
  rcases domain_cases is_domain with is_label | ⟨d, lab, old, is_label, is_cut⟩
  · obtain ⟨all, ⟨first, first_is, first_alnum⟩, _⟩ := is_label
    have all_l : ∀ b ∈ l, IsAlnum b ∨ b = 45 := fun b inside =>
      all b (List.mem_append_left _ inside)
    have first_l : ∀ b, l.head? = some b → IsAlnum b := by
      intro b is_head
      cases l with
      | nil => simp at is_head
      | cons head rest =>
        simp at is_head first_is
        rw [← is_head, first_is]; exact first_alnum
    rcases label_so_far l all_l first_l with empty | is_label | ⟨d, k, is_d, hyphens⟩
    · exact Or.inl empty
    · exact Or.inr (Or.inl (Domain.label is_label))
    · exact Or.inr (Or.inr (Or.inl ⟨d, k, Domain.label is_d, hyphens⟩))
  · have filled : lab ≠ [] := by
      rintro rfl
      obtain ⟨z, z_is, _⟩ := is_label.2.2
      simp at z_is
    obtain ⟨lab', y, lab_is⟩ := List.eq_nil_or_concat lab |>.resolve_left filled
    replace lab_is : lab = lab' ++ [y] := by rw [lab_is]; simp
    rw [lab_is, ← List.append_assoc] at is_cut
    have l_is : l = d ++ [46] ++ lab' := (List.append_inj' is_cut (by simp)).1
    obtain ⟨all, ⟨first, first_is, first_alnum⟩, _⟩ := is_label
    have all_l : ∀ b ∈ lab', IsAlnum b ∨ b = 45 := fun b inside =>
      all b (by rw [lab_is]; exact List.mem_append_left _ inside)
    have first_l : ∀ b, lab'.head? = some b → IsAlnum b := by
      intro b is_head
      rw [lab_is] at first_is
      cases lab' with
      | nil => simp at is_head
      | cons head rest =>
        simp at is_head first_is
        rw [← is_head, first_is]; exact first_alnum
    rcases label_so_far lab' all_l first_l with empty | is_label' | ⟨d', k, is_d', hyphens⟩
    · exact Or.inr (Or.inr (Or.inr ⟨d, old, by rw [l_is, empty, List.append_nil]⟩))
    · exact Or.inr (Or.inl (by rw [l_is]; exact Domain.join old is_label'))
    · refine Or.inr (Or.inr (Or.inl ⟨d ++ [46] ++ d', k, Domain.join old is_d', ?_⟩))
      rw [l_is, hyphens]
      simp

/-- The beginning of a domain name, with its last byte taken off, still begins a domain name. -/
theorem so_far_before_the_last_byte {l : List Nat} {x : Nat} (so_far : DomainSoFar (l ++ [x])) :
    DomainSoFar l := by
  rcases so_far with empty | whole | ⟨d, k, is_d, hyphens⟩ | ⟨d, is_d, dot⟩
  · exact absurd empty (by simp)
  · exact domain_so_far_before_the_last_byte whole
  · rw [List.replicate_succ', ← List.append_assoc] at hyphens
    have l_is : l = d ++ List.replicate k 45 := (List.append_inj' hyphens.symm (by simp)).1.symm
    cases k with
    | zero => exact Or.inr (Or.inl (by simpa [l_is] using is_d))
    | succ k => exact Or.inr (Or.inr (Or.inl ⟨d, k, is_d, l_is⟩))
  · have l_is : l = d := (List.append_inj' dot.symm (by simp)).1.symm
    exact Or.inr (Or.inl (l_is ▸ is_d))

/-- Every beginning of the beginning of a domain name is one: the first `n` bytes of it. -/
theorem so_far_of_a_beginning {l : List Nat} (so_far : DomainSoFar l) (n : Nat) :
    DomainSoFar (l.take n) := by
  induction l using List.reverseRecOn with
  | nil => simpa using so_far
  | append_singleton before y ih =>
    rcases Nat.lt_or_ge n (before ++ [y]).length with short | long
    · have : n ≤ before.length := by simp at short; omega
      rw [List.take_append_of_le_length this]
      exact ih (so_far_before_the_last_byte so_far)
    · rw [List.take_of_length_le long]; exact so_far

/-- A domain name does not end in a dot or a hyphen, and is not empty. -/
theorem domain_does_not_end_in_a_separator {d : List Nat} (is_domain : Domain d) :
    d ≠ [] ∧ d.getLast? ≠ some 46 ∧ d.getLast? ≠ some 45 := by
  obtain ⟨z, z_is, z_alnum⟩ := domain_ends_in_alnum is_domain
  unfold IsAlnum IsLower IsDigit at z_alnum
  refine ⟨fun empty => by simp [empty] at z_is, fun is_dot => ?_, fun is_hyphen => ?_⟩
  · rw [z_is] at is_dot; have := Option.some.inj is_dot; omega
  · rw [z_is] at is_hyphen; have := Option.some.inj is_hyphen; omega

/-- A byte that is not a letter or a digit, in the beginning of a domain name, is a hyphen after
something that does not end in a dot, or a dot after something that ends in neither. -/
theorem so_far_with_a_separator {l : List Nat} {x : Nat} (so_far : DomainSoFar (l ++ [x]))
    (not_alnum : ¬ IsAlnum x) :
    l ≠ [] ∧ l.getLast? ≠ some 46 ∧ (x = 45 ∨ (x = 46 ∧ l.getLast? ≠ some 45)) := by
  rcases so_far with empty | whole | ⟨d, k, is_d, hyphens⟩ | ⟨d, is_d, dot⟩
  · exact absurd empty (by simp)
  · obtain ⟨z, z_is, z_alnum⟩ := domain_ends_in_alnum whole
    rw [List.getLast?_append_of_ne_nil _ (by simp)] at z_is
    simp at z_is
    exact absurd (z_is ▸ z_alnum) not_alnum
  · obtain ⟨d_filled, _, _⟩ := domain_does_not_end_in_a_separator is_d
    rw [List.replicate_succ', ← List.append_assoc] at hyphens
    obtain ⟨l_is, x_is⟩ := List.append_inj' hyphens.symm (by simp)
    simp only [List.cons.injEq, and_true] at x_is
    rw [← l_is]
    refine ⟨by simp [d_filled], ?_, Or.inl x_is.symm⟩
    cases k with
    | zero => simpa using (domain_does_not_end_in_a_separator is_d).2.1
    | succ k =>
      rw [List.getLast?_append_of_ne_nil _ (by simp)]
      simp [List.getLast?_replicate]
  · obtain ⟨d_filled, not_dot, not_hyphen⟩ := domain_does_not_end_in_a_separator is_d
    obtain ⟨l_is, x_is⟩ := List.append_inj' dot.symm (by simp)
    simp only [List.cons.injEq, and_true] at x_is
    rw [← l_is]
    exact ⟨d_filled, not_dot, Or.inr ⟨x_is.symm, not_hyphen⟩⟩

end RefCore
