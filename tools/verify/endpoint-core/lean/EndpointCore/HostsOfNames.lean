-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: two plain facts about the host of a name (`HostOf` of Spec.lean): a name
-- has only one host, and the host is what is before the last `:` of the part of the name before
-- its first `/` or `@`, so that the scans of the crate find it; and a host that ends with a `.`
-- and a domain is "some bytes, a `.` and the domain".
-- Why it is needed: a wildcard prefix `*.domain` governs a name by its host, and `governs` finds
-- the host with two loops and then looks at the end of it.
-- Read before this file: Spec.lean.
-- Notation: `l <:+ m` is "l is the end of m"; `m[i]` is the element at the place `i` (from 0).
import EndpointCore.Spec

open Aeneas Aeneas.Std Result velarx_endpoint_core

namespace EndpointCore

/-- A name has one host: two hosts that `HostOf` accepts for it are the same bytes. -/
theorem a_name_has_one_host (ref one other : Bytes) (is_one : HostOf ref one)
    (is_other : HostOf ref other) : one = other := by
  obtain ⟨authority, is_authority, one_cases⟩ := is_one
  obtain ⟨authority', is_authority', other_cases⟩ := is_other
  have same : authority = authority' := by rw [is_authority, is_authority']
  subst same
  rcases one_cases with ⟨no_colon, one_is⟩ | ⟨port, split_one, no_colon_in_port⟩
  · rcases other_cases with ⟨_, other_is⟩ | ⟨port', split_other, _⟩
    · rw [one_is, other_is]
    · exact absurd (by rw [split_other]; simp) no_colon
  · rcases other_cases with ⟨no_colon, _⟩ | ⟨port', split_other, no_colon_in_port'⟩
    · exact absurd (by rw [split_one]; simp) no_colon
    · rw [split_one] at split_other
      rcases List.append_eq_append_iff.mp split_other with
        ⟨more, other_is, rest⟩ | ⟨more, one_is, rest⟩
      · cases more with
        | nil => simpa using other_is.symm
        | cons x rest_of_more =>
          simp only [List.cons_append, List.cons.injEq] at rest
          exact absurd (by rw [rest.2]; simp) no_colon_in_port
      · cases more with
        | nil => simpa using one_is
        | cons x rest_of_more =>
          simp only [List.cons_append, List.cons.injEq] at rest
          exact absurd (by rw [rest.2]; simp) no_colon_in_port'

/-- A host of more than the domain, that ends with the domain, and has a `.` just before it, is
some bytes, a `.` and the domain; and the other way round. -/
theorem a_host_ends_with_a_dot_and_the_domain (host domain : Bytes) :
    (domain.length < host.length ∧ domain <:+ host ∧
      host[host.length - domain.length - 1]? = some Dot)
      ↔ ∃ front, host = front ++ Dot :: domain := by
  constructor
  · rintro ⟨longer, ⟨front', is_host⟩, dot⟩
    subst is_host
    rcases List.eq_nil_or_concat front' with is_nil | ⟨front, last, is_concat⟩
    · subst is_nil
      simp at longer
    · subst is_concat
      simp only [List.concat_eq_append] at longer dot ⊢
      refine ⟨front, ?_⟩
      have place : (front ++ [last] ++ domain).length - domain.length - 1 = front.length := by
        simp
        omega
      rw [place] at dot
      have last_is : last = Dot := by
        rw [List.append_assoc, List.getElem?_append_right (by omega)] at dot
        simpa using dot
      simp [last_is]
  · rintro ⟨front, is_host⟩
    subst is_host
    refine ⟨by simp; omega, ⟨front ++ [Dot], by simp⟩, ?_⟩
    have place : (front ++ Dot :: domain).length - domain.length - 1 = front.length := by
      simp
      omega
    rw [place, List.getElem?_append_right (by omega)]
    simp

end EndpointCore
