-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `local_v6` answers: `true` exactly when the number of the 16 bytes is in a
--   prefix of `LocalV6`, or in a form of `Embedded` whose IPv4 address is local.
-- Why it is needed: it is rule 3 of lib.rs; the function is two loops, over `LOCAL_V6` and over `EMBEDDED`,
--   and the second stops at the first form the address is in, which is the whole answer only because no
--   address is in two forms (`forms_apart`).
-- Read before this file: TheV4.lean.
-- Notation: as in TheV4.lean; `Embeds n e` says the number `n` is in the form `e` and the IPv4 address in
--   it is local; `decide +kernel` has Lean's kernel compute a statement about fixed numbers.
import AddrCore.TheV4
open Aeneas Aeneas.Std Result velarx_addr_core
namespace AddrCore

/-- The table `LOCAL_V6` of the code, as numbers, is `LocalV6` of the statement. -/
theorem table_v6 : LOCAL_V6.val.map (fun p => (p.1.val, p.2.val)) = LocalV6 := by
  unfold LOCAL_V6 LocalV6 Ipv6
  rfl

/-- every prefix of the table is aligned and has between 1 and 128 bits -/
theorem prefixes_v6 : ∀ q ∈ LocalV6, 1 ≤ q.2 ∧ q.2 ≤ 128 ∧ q.1 % 2 ^ (128 - q.2) = 0 := by
  unfold LocalV6 Ipv6
  decide +kernel

/-- the entry `j` of the table of the code is the entry `j` of the table of the statement -/
theorem entry_v6 (j : Nat) (inside : j < 11) :
    ∃ p, LOCAL_V6.val[j]? = some p ∧ LocalV6[j]? = some (p.1.val, p.2.val) := by
  have length : LOCAL_V6.val.length = 11 := by simp
  have there : LOCAL_V6.val[j]? = some LOCAL_V6.val[j] := by simp [length, inside]
  refine ⟨LOCAL_V6.val[j], there, ?_⟩
  rw [← table_v6]
  simp [List.getElem?_map, there]

/-- The loop of `in_local_v6`, from the entry `i` of the table `LOCAL_V6`: `true` exactly when the number is in one of the prefixes from the entry `i` on. -/
theorem in_local_v6_loop_is (a : Std.U128) (i : Std.Usize) (inside : i.val ≤ 11) :
    in_local_v6_loop a i ⦃ r =>
      r = true ↔ ∃ q ∈ LocalV6.drop i.val, InPrefix 128 a.val q.1 q.2 ⦄ := by
  unfold in_local_v6_loop
  -- the loop keeps: what is left to try from the entry `j` holds exactly when what was left from
  -- the entry it started at does (it ends at the first entry that holds), and `j` goes up
  apply loop.spec_decr_nat (fun j => 11 - j.val)
    (fun j => j.val ≤ 11 ∧ ((∃ q ∈ LocalV6.drop j.val, InPrefix 128 a.val q.1 q.2) ↔
        ∃ q ∈ LocalV6.drop i.val, InPrefix 128 a.val q.1 q.2))
  · intro j ⟨inside_j, same⟩
    unfold in_local_v6_loop.body
    -- the length of the table
    step as ⟨ s, h_s ⟩
    have length : s.len.val = 11 := by rw [h_s]; simp [Slice.len, Array.to_slice]
    by_cases below : j < s.len
    · simp only [below, ite_true]
      have below' : j.val < 11 := by scalar_tac
      step as ⟨ p, h_p ⟩
      obtain ⟨p', is_p, entry⟩ := entry_v6 j.val below'
      have p_is : p = p' := by simp_all
      subst p_is
      obtain ⟨first, len⟩ := p
      simp only at entry ⊢
      obtain ⟨one_le, le_128, aligned⟩ := prefixes_v6 _ (List.mem_of_getElem? entry)
      simp only at one_le le_128 aligned
      -- the number is xor-ed with the first address and shifted right: zero when it is in the prefix
      step as ⟨ i2, h2 ⟩
      step as ⟨ i3, h3 ⟩
      step as ⟨ i4, h4 ⟩
      have found : i4 = 0#u128 ↔ InPrefix 128 a.val first.val len.val := by
        rw [Std.UScalar.eq_equiv, h4, h2, UScalar.val_xor, h3]
        exact in_block _ _ _ aligned
      -- an entry holds: the loop returns, and what is left from `j` holds by that entry
      split
      · refine (WP.spec_ok _).mpr ?_
        simp only [true_iff]
        rename_i hit
        have := found.mp hit
        exact same.mp ((drop_step _ _ _ _ entry).mpr (Or.inl this))
      -- the entry does not hold: the loop goes on to the next, and the entry adds nothing
      · rename_i miss
        step as ⟨ i5, h5 ⟩
        have not_hit : ¬ InPrefix 128 a.val first.val len.val := fun hit => miss (found.mpr hit)
        refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        rw [← same, drop_step _ _ _ _ entry, h5]
        simp [not_hit]
    -- the table is at its end: nothing is left to hold
    · have at_end : j.val = 11 := by scalar_tac
      simp only [below, ite_false]
      refine (WP.spec_ok _).mpr ?_
      rw [at_end] at same
      have none : ¬ ∃ q ∈ LocalV6.drop 11, InPrefix 128 a.val q.1 q.2 := by simp [LocalV6]
      exact ⟨fun h => Bool.noConfusion h, fun found => absurd (same.mpr found) none⟩
  · exact ⟨inside, Iff.rfl⟩


/-- `in_local_v6` says `true` exactly when the number is in a prefix of `LocalV6`. -/
@[step]
theorem in_local_v6_is (a : Std.U128) :
    in_local_v6 a ⦃ r => r = true ↔ ∃ q ∈ LocalV6, InPrefix 128 a.val q.1 q.2 ⦄ := by
  unfold in_local_v6
  exact in_local_v6_loop_is a 0#usize (by scalar_tac)

/-- The table `EMBEDDED` of the code, as numbers, is `Embedded` of the statement. -/
theorem table_embedded : EMBEDDED.val.map (fun p => (p.1.val, p.2.1.val, p.2.2.val)) = Embedded := by
  unfold EMBEDDED Embedded Ipv6
  rfl

/-- every embedded form is aligned, has between 1 and 128 bits, and shifts by less than 128 -/
theorem forms_embedded : ∀ e ∈ Embedded, 1 ≤ e.2.1 ∧ e.2.1 ≤ 128 ∧ e.1 % 2 ^ (128 - e.2.1) = 0 ∧ e.2.2 < 128 := by
  unfold Embedded Ipv6
  decide +kernel

/-- no address is in two embedded forms -/
theorem forms_apart : Embedded.Pairwise (fun e f =>
    e.1 + 2 ^ (128 - e.2.1) ≤ f.1 ∨ f.1 + 2 ^ (128 - f.2.1) ≤ e.1) := by
  unfold Embedded Ipv6
  decide +kernel

/-- The entry `j` of the table `EMBEDDED` of the code is the entry `j` of `Embedded`. -/
theorem entry_embedded (j : Nat) (inside : j < 5) :
    ∃ p, EMBEDDED.val[j]? = some p ∧ Embedded[j]? = some (p.1.val, p.2.1.val, p.2.2.val) := by
  have length : EMBEDDED.val.length = 5 := by simp
  have there : EMBEDDED.val[j]? = some EMBEDDED.val[j] := by simp [length, inside]
  refine ⟨EMBEDDED.val[j], there, ?_⟩
  rw [← table_embedded]
  simp [List.getElem?_map, there]

/-- an address in the form at `j` is in no form after it -/
theorem later_forms_do_not_match (n j : Nat) (q : Nat × Nat × Nat) (at_j : Embedded[j]? = some q)
    (hit : InPrefix 128 n q.1 q.2.1) : ∀ e ∈ Embedded.drop (j + 1), ¬ InPrefix 128 n e.1 e.2.1 := by
  obtain ⟨inside, is_q⟩ := List.getElem?_eq_some_iff.mp at_j
  have apart := forms_apart.sublist (List.drop_sublist j Embedded)
  rw [List.drop_eq_getElem_cons inside, is_q, List.pairwise_cons] at apart
  intro e there ⟨e_lo, e_hi⟩
  obtain ⟨q_lo, q_hi⟩ := hit
  have := apart.1 e there
  omega

/-- one embedded form, with the IPv4 address in it, read as a statement on the number `n` -/
def Embeds (n : Nat) (e : Nat × Nat × Nat) : Prop :=
  InPrefix 128 n e.1 e.2.1 ∧ IsLocalV4 (EmbeddedV4 n e.2.2)

/-- The loop of `embeds_local_v4`, from the entry `i` of `EMBEDDED`: it stops at the first form the number is in and answers for the IPv4 address in it; since no number is in two forms (`later_forms_do_not_match`), it says `true` exactly when the number is in a form from the entry `i` on whose IPv4 address is local. -/
theorem embeds_local_v4_loop_is (a : Std.U128) (i : Std.Usize) (inside : i.val ≤ 5) :
    embeds_local_v4_loop a i ⦃ r =>
      r = true ↔ ∃ e ∈ Embedded.drop i.val, Embeds a.val e ⦄ := by
  unfold embeds_local_v4_loop
  -- the loop keeps: what is left to try from the entry `j` holds exactly when what was left from
  -- the entry it started at does (it ends at the first entry that holds), and `j` goes up
  apply loop.spec_decr_nat (fun j => 5 - j.val)
    (fun j => j.val ≤ 5 ∧ ((∃ e ∈ Embedded.drop j.val, Embeds a.val e) ↔
        ∃ e ∈ Embedded.drop i.val, Embeds a.val e))
  · intro j ⟨inside_j, same⟩
    unfold embeds_local_v4_loop.body
    -- the length of the table
    step as ⟨ s, h_s ⟩
    have length : s.len.val = 5 := by rw [h_s]; simp [Slice.len, Array.to_slice]
    by_cases below : j < s.len
    · simp only [below, ite_true]
      have below' : j.val < 5 := by scalar_tac
      step as ⟨ t, h_t ⟩
      obtain ⟨t', is_t, entry⟩ := entry_embedded j.val below'
      have t_is : t = t' := by simp_all
      subst t_is
      obtain ⟨first, len, shift⟩ := t
      simp only at entry ⊢
      obtain ⟨one_le, le_128, aligned, small⟩ := forms_embedded _ (List.mem_of_getElem? entry)
      simp only at one_le le_128 aligned small
      -- the number is xor-ed with the first address and shifted right: zero when it is in the prefix
      step as ⟨ i2, h2 ⟩
      step as ⟨ i3, h3 ⟩
      step as ⟨ i4, h4 ⟩
      have found : i4 = 0#u128 ↔ InPrefix 128 a.val first.val len.val := by
        rw [Std.UScalar.eq_equiv, h4, h2, UScalar.val_xor, h3]
        exact in_block _ _ _ aligned
      -- the number is in the form: the loop returns the answer for the IPv4 address in it
      split
      · rename_i hit
        step as ⟨ i5, h5 ⟩
        step as ⟨ i6, h6 ⟩
        step as ⟨ b, h_b ⟩
        have in_form : InPrefix 128 a.val first.val len.val := found.mp hit
        have v4_is : i6.val = EmbeddedV4 a.val shift.val := by
          simp [h6, h5, EmbeddedV4, Nat.shiftRight_eq_div_pow]
        rw [h_b, ← same, drop_step _ _ _ (Embeds a.val) entry, v4_is]
        have later := later_forms_do_not_match _ _ _ entry in_form
        constructor
        · intro local_v4
          exact Or.inl ⟨in_form, local_v4⟩
        · rintro (⟨_, local_v4⟩ | ⟨e, there, in_e, _⟩)
          · exact local_v4
          · exact absurd in_e (later e there)
      -- the entry does not hold: the loop goes on to the next, and the entry adds nothing
      · rename_i miss
        step as ⟨ i5, h5 ⟩
        have not_hit : ¬ InPrefix 128 a.val first.val len.val := fun hit => miss (found.mpr hit)
        refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        rw [← same, drop_step _ _ _ (Embeds a.val) entry, h5]
        simp [Embeds, not_hit]
    -- the table is at its end: nothing is left to hold
    · have at_end : j.val = 5 := by scalar_tac
      simp only [below, ite_false]
      refine (WP.spec_ok _).mpr ?_
      rw [at_end] at same
      have none : ¬ ∃ e ∈ Embedded.drop 5, Embeds a.val e := by simp [Embedded]
      exact ⟨fun h => Bool.noConfusion h, fun found => absurd (same.mpr found) none⟩
  · exact ⟨inside, Iff.rfl⟩

/-- The right side of `WhatIsLocalExactly` for IPv6, for a number `n`. -/
def IsLocalV6 (n : Nat) : Prop :=
  (∃ q ∈ LocalV6, InPrefix 128 n q.1 q.2) ∨
  ∃ e ∈ Embedded, InPrefix 128 n e.1 e.2.1 ∧ IsLocalV4 (EmbeddedV4 n e.2.2)

/-- `embeds_local_v4` says `true` exactly when the number is in a form of `Embedded` whose IPv4 address is local. -/
@[step]
theorem embeds_local_v4_is (a : Std.U128) :
    embeds_local_v4 a ⦃ r => r = true ↔ ∃ e ∈ Embedded, InPrefix 128 a.val e.1 e.2.1 ∧
      IsLocalV4 (EmbeddedV4 a.val e.2.2) ⦄ := by
  unfold embeds_local_v4
  exact embeds_local_v4_loop_is a 0#usize (by scalar_tac)

/-- `local_v6` returns, and says `true` exactly when the number of the 16 bytes is local (in a prefix of `LocalV6`, or in a form of `Embedded` with a local IPv4 address in it). -/
@[step]
theorem local_v6_is (a : Std.Array Std.U8 16#usize) :
    local_v6 a ⦃ r => r = true ↔ IsLocalV6 (Number a.val) ⦄ := by
  unfold local_v6 IsLocalV6
  step as ⟨ n, h_n ⟩
  step as ⟨ b, h_b ⟩
  rw [← h_n]
  by_cases local_prefix : b = true
  · simp only [local_prefix, ite_true]
    refine (WP.spec_ok _).mpr ?_
    simp [h_b.mp local_prefix]
  · simp only [local_prefix, Bool.false_eq_true, ite_false]
    step as ⟨ r, h_r ⟩
    rw [h_r]
    have : ¬ ∃ q ∈ LocalV6, InPrefix 128 n.val q.1 q.2 := fun found => local_prefix (h_b.mpr found)
    simp [this]

end AddrCore
