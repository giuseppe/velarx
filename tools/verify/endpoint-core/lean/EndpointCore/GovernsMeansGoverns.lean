-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `wildcard` answers `true` exactly for a wildcard prefix, and `governs`
-- answers `true` exactly when the prefix of the block governs the name, as `Governs` of Spec.lean
-- says it.
-- Why it is needed: `select` asks `governs` of every block, so the claim about the block chosen
-- goes through it.
-- Read before this file: Spec.lean, ComparingBytes.lean, CopyingBytes.lean, ScanningTheName.lean,
-- HostsOfNames.lean.
-- Notation: `step as ⟨ x, hx ⟩` runs one line of a Rust function and names its result `x` and what
-- is known of it `hx`; `blocks.val[b]?` is `some` of the block at the place `b`, or `none`.
import EndpointCore.Spec
import EndpointCore.ComparingBytes
import EndpointCore.CopyingBytes
import EndpointCore.ScanningTheName
import EndpointCore.HostsOfNames
import EndpointCore.TakeWhileFacts
import EndpointCore.VectorsAreSlices

open Aeneas Aeneas.Std Result velarx_endpoint_core

namespace EndpointCore

/-- Bytes that begin with two bytes are a wildcard prefix exactly when the two are `*` and `.`. -/
theorem two_bytes_make_a_wildcard (first second : Std.U8) (rest : Bytes) :
    IsWildcard (first :: second :: rest) ↔ first = Star ∧ second = Dot := by
  constructor
  · rintro ⟨domain, is_wildcard⟩
    simp only [List.cons.injEq] at is_wildcard
    exact ⟨is_wildcard.1, is_wildcard.2.1⟩
  · rintro ⟨is_star, is_dot⟩
    exact ⟨rest, by rw [is_star, is_dot]⟩

/-- **`wildcard`** answers `true` exactly for a prefix that begins with `*.`. -/
theorem wildcard_says (pfx : Slice Std.U8) :
    wildcard pfx ⦃ r => r = true ↔ IsWildcard pfx.val ⦄ := by
  unfold wildcard
  by_cases long : 2#usize ≤ Slice.len pfx
  · have long' : 2 ≤ pfx.length := by scalar_tac
    simp only [ge_iff_le, long, ite_true]
    obtain ⟨a, c, rest, is_list⟩ : ∃ a c rest, pfx.val = a :: c :: rest := by
      match h : pfx.val with
      | a :: c :: rest => exact ⟨a, c, rest, rfl⟩
      | [] => simp [Slice.length, h] at long'
      | [_] => simp [Slice.length, h] at long'
    step as ⟨ first, is_first ⟩
    have first_is : first = a := by simp [is_first, is_list]
    by_cases is_star : first = 42#u8
    · simp only [is_star, ite_true]
      step as ⟨ second, is_second ⟩
      have second_is : second = c := by simp [is_second, is_list]
      rw [is_list, two_bytes_make_a_wildcard]
      simp [Star, Dot, ← first_is, ← second_is, is_star]
    · simp only [is_star, ite_false]
      refine (WP.spec_ok _).mpr ?_
      rw [is_list, two_bytes_make_a_wildcard]
      simp [Star, ← first_is, is_star]
  · have short : pfx.length < 2 := by scalar_tac
    simp only [ge_iff_le, long, ite_false]
    refine (WP.spec_ok _).mpr ?_
    constructor
    · intro absurd
      cases absurd
    · rintro ⟨domain, is_wildcard⟩
      have : pfx.val.length = 2 + domain.length := by
        simp [is_wildcard]
        omega
      have : pfx.val.length = pfx.length := rfl
      omega

/-- A wildcard prefix governs a name exactly when the host of the name is some bytes, a `.` and the
domain of the prefix (what follows its `*.`). -/
theorem a_wildcard_governs_by_the_host (pfx ref host : Bytes) (wild : IsWildcard pfx)
    (is_host : HostOf ref host) :
    Governs pfx ref ↔ ∃ front, host = front ++ Dot :: pfx.drop 2 := by
  obtain ⟨domain, is_domain⟩ := wild
  subst is_domain
  constructor
  · rintro (⟨_, domain', host', front, same, is_host', is_front⟩ | ⟨not_wild, _⟩)
    · simp only [List.cons.injEq, true_and] at same
      subst same
      rw [a_name_has_one_host ref host host' is_host is_host']
      exact ⟨front, by simpa using is_front⟩
    · exact absurd ⟨domain, rfl⟩ not_wild
  · rintro ⟨front, is_front⟩
    exact Or.inl ⟨⟨domain, rfl⟩, domain, host, front, rfl, is_host, by simpa using is_front⟩

/-- A plain prefix governs only a name that it begins. -/
theorem a_plain_prefix_governs_only_what_it_begins (pfx ref : Bytes) (plain : ¬ IsWildcard pfx)
    (governs : Governs pfx ref) : pfx <+: ref := by
  rcases governs with ⟨wild, _⟩ | ⟨_, same | ⟨boundary, rest, _, split⟩⟩
  · exact absurd wild plain
  · rw [same]
  · rw [split]
    exact List.prefix_append _ _

/-- A plain prefix that is the whole name governs it. -/
theorem a_plain_prefix_governs_itself (pfx ref : Bytes) (plain : ¬ IsWildcard pfx)
    (begins : pfx <+: ref) (not_longer : ref.length ≤ pfx.length) : Governs pfx ref := by
  refine Or.inr ⟨plain, Or.inl ?_⟩
  exact (begins.eq_of_length (by have := begins.length_le; omega)).symm

/-- A plain prefix that begins a longer name governs it exactly when the byte after it is `/` or
`@`. -/
theorem a_plain_prefix_governs_by_the_next_byte (pfx ref : Bytes) (plain : ¬ IsWildcard pfx)
    (begins : pfx <+: ref) (longer : pfx.length < ref.length) (next : Std.U8)
    (is_next : ref[pfx.length]? = some next) :
    Governs pfx ref ↔ next = Slash ∨ next = AtSign := by
  obtain ⟨rest, split⟩ := begins
  subst split
  have next_is : (pfx ++ rest)[pfx.length]? = rest[0]? := by
    rw [List.getElem?_append_right (by omega)]
    simp
  rw [next_is] at is_next
  cases rest with
  | nil => simp at longer
  | cons first rest' =>
    simp only [List.getElem?_cons_zero, Option.some.injEq] at is_next
    subst is_next
    constructor
    · rintro (⟨wild, _⟩ | ⟨_, same | ⟨boundary, rest'', is_boundary, split⟩⟩)
      · exact absurd wild plain
      · have := congrArg List.length same
        simp at this
      · have same := List.append_cancel_left split
        simp only [List.cons.injEq] at same
        rw [same.1]
        exact is_boundary
    · intro boundary
      exact Or.inr ⟨plain, Or.inr ⟨first, rest', boundary, rfl⟩⟩

/-- **`governs`** answers `true` exactly when the prefix of the block number `b` governs the
name. -/
theorem governs_says (blocks : Slice Block) (b : Std.Usize) (ref : Slice Std.U8) (block : Block)
    (is_block : blocks.val[b.val]? = some block) :
    governs blocks b ref ⦃ r => r = true ↔ Governs block.prefix.val ref.val ⦄ := by
  have inside : b.val < blocks.val.length := (List.getElem?_eq_some_iff.mp is_block).1
  unfold governs
  step as ⟨ blk, is_blk ⟩
  have blk_is : blk = block := by
    have := List.getElem?_eq_getElem inside
    rw [is_block] at this
    simp [is_blk, Option.some.inj this]
  subst blk_is
  step with wildcard_says as ⟨ is_wild, is_wild_says ⟩
  by_cases wild : is_wild = true
  · simp only [wild, ite_true]
    step with governs_goes_to_the_end_of_the_host as ⟨ stop, is_stop ⟩
    have stop_inside : stop.val ≤ ref.length := by
      rw [is_stop]
      exact take_while_is_not_longer _ ref.val
    step with governs_goes_to_the_last_colon ref stop stop_inside as ⟨ port, port_inside, port_is ⟩
    step with tail_is_the_end as ⟨ domain, is_domain ⟩
    step as ⟨ host_slice, is_host_slice ⟩
    step with tail_is_the_end as ⟨ host, is_host ⟩
    have same_length : ref.val.length = ref.length := rfl
    have domain_is : domain.val = blk.prefix.val.drop 2 := by
      rw [is_domain]
      simp
    have host_is : host.val = ref.val.take port.val := by
      rw [is_host, is_host_slice]
      simp
    have wild_prefix : IsWildcard blk.prefix.val := by simpa using is_wild_says.mp wild
    -- the host the loops found is the host of the name
    have authority_is : ref.val.take stop.val = ref.val.takeWhile
        (fun b => decide (b ≠ Slash ∧ b ≠ AtSign)) := by
      rw [is_stop]
      exact take_while_is_the_beginning _ ref.val
    have host_of : HostOf ref.val host.val := by
      refine ⟨ref.val.take stop.val, authority_is, ?_⟩
      rcases port_is with ⟨no_colon, is_stop_place⟩ | ⟨before, is_colon, none_after⟩
      · left
        rw [is_stop_place] at host_is
        exact ⟨no_colon, host_is⟩
      · right
        refine ⟨(ref.val.take stop.val).drop (port.val + 1), ?_, none_after⟩
        have place : port.val < (ref.val.take stop.val).length := by
          simp only [List.length_take]
          omega
        have colon_there : (ref.val.take stop.val)[port.val] = Colon := by
          have := List.getElem?_eq_getElem place
          rw [is_colon] at this
          exact (Option.some.inj this).symm
        rw [host_is]
        conv => lhs; rw [← List.take_append_drop port.val (ref.val.take stop.val)]
        rw [List.drop_eq_getElem_cons place, colon_there, List.take_take,
          Nat.min_eq_left port_inside]
    rw [a_wildcard_governs_by_the_host _ _ _ wild_prefix host_of, ← domain_is]
    rw [← a_host_ends_with_a_dot_and_the_domain]
    have host_len : host.len.val = host.val.length := alloc.vec.Vec.len_val host
    have domain_len : domain.len.val = domain.val.length := alloc.vec.Vec.len_val domain
    by_cases big : host.len > domain.len
    · have big' : domain.val.length < host.val.length := by scalar_tac
      simp only [big, ite_true]
      step with ends_with_is_the_end as ⟨ ends, is_ends ⟩
      by_cases is_end : ends = true
      · simp only [is_end, ite_true]
        step as ⟨ i4, is_i4 ⟩
        step as ⟨ i5, is_i5 ⟩
        step as ⟨ i6, is_i6 ⟩
        have suffix : domain.val <:+ host.val := by simpa using is_ends.mp is_end
        have place : i5.val = host.val.length - domain.val.length - 1 := by omega
        have at_place : host.val[host.val.length - domain.val.length - 1]? = some i6 := by
          rw [← place, is_i6]
          exact List.getElem?_eq_getElem _
        simp [big', suffix, at_place, Dot]
      · simp only [is_end]
        refine (WP.spec_ok _).mpr ?_
        have no_suffix : ¬ domain.val <:+ host.val := by
          intro suffix
          exact is_end (is_ends.mpr (by simpa using suffix))
        simp [no_suffix]
    · simp only [big, ite_false]
      refine (WP.spec_ok _).mpr ?_
      have not_longer : ¬ domain.val.length < host.val.length := by scalar_tac
      simp [not_longer]
  · have plain : ¬ IsWildcard blk.prefix.val := by
      intro is_wild_prefix
      exact wild (is_wild_says.mpr (by simpa using is_wild_prefix))
    have wild' : is_wild = false := by simpa using wild
    simp only [wild', Bool.false_eq_true, ↓reduceIte]
    step with starts_with_is_the_beginning as ⟨ yes, is_yes ⟩
    have prefix_len : blk.prefix.len.val = blk.prefix.val.length := alloc.vec.Vec.len_val _
    have same_length : ref.val.length = ref.length := rfl
    by_cases begins : yes = true
    · have begins' : blk.prefix.val <+: ref.val := by simpa using is_yes.mp begins
      simp only [begins, ite_true]
      by_cases longer : blk.prefix.len < Slice.len ref
      · have longer' : blk.prefix.val.length < ref.val.length := by scalar_tac
        simp only [gt_iff_lt, longer, ite_true]
        step as ⟨ next, is_next ⟩
        have at_next : ref.val[blk.prefix.val.length]? = some next := by
          rw [is_next]
          exact List.getElem?_eq_getElem _
        rw [a_plain_prefix_governs_by_the_next_byte _ _ plain begins' longer' next at_next]
        by_cases is_slash : next = 47#u8
        · simp [is_slash, Slash]
        · simp [is_slash, Slash, AtSign]
      · have not_longer : ref.val.length ≤ blk.prefix.val.length := by scalar_tac
        simp only [gt_iff_lt, longer, ite_false]
        refine (WP.spec_ok _).mpr ?_
        simp [a_plain_prefix_governs_itself _ _ plain begins' not_longer]
    · have no_begin : ¬ blk.prefix.val <+: ref.val := by
        intro begins'
        exact begins (is_yes.mpr (by simpa using begins'))
      simp only [begins]
      refine (WP.spec_ok _).mpr ?_
      have : ¬ Governs blk.prefix.val ref.val := fun governs =>
        no_begin (a_plain_prefix_governs_only_what_it_begins _ _ plain governs)
      simp [this]

end EndpointCore
