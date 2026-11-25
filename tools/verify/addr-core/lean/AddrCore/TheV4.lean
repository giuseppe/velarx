-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `local_v4` answers: `true` exactly when the number of the 4 bytes is in a
--   prefix of `LocalV4`.
-- Why it is needed: it is the claim of rule 2 of lib.rs; the loop over the table `LOCAL_V4` is the whole
--   function, and its proof is by the entry the loop is at.
-- Read before this file: TheNumbers.lean, TheMatch.lean.
-- Notation: `LOCAL_V4.val` is the list of the table of the code; `l.drop i` is `l` without its first `i`
--   entries; `∃ q ∈ l, P q` says some entry `q` of `l` satisfies `P`.
import AddrCore.TheMatch
open Aeneas Aeneas.Std Result velarx_addr_core
namespace AddrCore

/-- The table `LOCAL_V4` of the code, as numbers, is `LocalV4` of the statement (the same 15 pairs in the same order). -/
theorem table_v4 : LOCAL_V4.val.map (fun p => (p.1.val, p.2.val)) = LocalV4 := by
  unfold LOCAL_V4 LocalV4 Ipv4
  rfl

/-- every prefix of the table is aligned and has between 1 and 32 bits -/
theorem prefixes_v4 : ∀ q ∈ LocalV4, 1 ≤ q.2 ∧ q.2 ≤ 32 ∧ q.1 % 2 ^ (32 - q.2) = 0 := by
  unfold LocalV4 Ipv4
  decide +kernel

/-- the entry `j` of the table of the code is the entry `j` of the table of the statement -/
theorem entry_v4 (j : Nat) (inside : j < 15) :
    ∃ p, LOCAL_V4.val[j]? = some p ∧ LocalV4[j]? = some (p.1.val, p.2.val) := by
  have length : LOCAL_V4.val.length = 15 := by simp
  have there : LOCAL_V4.val[j]? = some LOCAL_V4.val[j] := by simp [length, inside]
  refine ⟨LOCAL_V4.val[j], there, ?_⟩
  rw [← table_v4]
  simp [List.getElem?_map, there]

/-- what is left to try at the entry `j` is the entry `j` and what is left at `j + 1` -/
theorem drop_step {α : Type} (l : List α) (j : Nat) (q : α) (P : α → Prop)
    (at_j : l[j]? = some q) : (∃ r ∈ l.drop j, P r) ↔ P q ∨ ∃ r ∈ l.drop (j + 1), P r := by
  obtain ⟨inside, is_q⟩ := List.getElem?_eq_some_iff.mp at_j
  rw [List.drop_eq_getElem_cons inside, is_q]
  simp

/-- The loop of `local_number_v4`, from the entry `i` of the table: it says `true` exactly when the number is in one of the prefixes from the entry `i` on (it stops at the first that holds; the `xor` shifted right is zero exactly when the number is in the block, see `in_block`). -/
theorem local_number_v4_loop_is (a : Std.U32) (i : Std.Usize) (inside : i.val ≤ 15) :
    local_number_v4_loop a i ⦃ r =>
      r = true ↔ ∃ q ∈ LocalV4.drop i.val, InPrefix 32 a.val q.1 q.2 ⦄ := by
  unfold local_number_v4_loop
  -- the loop keeps: what is left to try from the entry `j` holds exactly when what was left from
  -- the entry it started at does (it ends at the first entry that holds), and `j` goes up
  apply loop.spec_decr_nat (fun j => 15 - j.val)
    (fun j => j.val ≤ 15 ∧ ((∃ q ∈ LocalV4.drop j.val, InPrefix 32 a.val q.1 q.2) ↔
        ∃ q ∈ LocalV4.drop i.val, InPrefix 32 a.val q.1 q.2))
  · intro j ⟨inside_j, same⟩
    unfold local_number_v4_loop.body
    -- the length of the table
    step as ⟨ s, h_s ⟩
    have length : s.len.val = 15 := by rw [h_s]; simp [Slice.len, Array.to_slice]
    by_cases below : j < s.len
    · simp only [below, ite_true]
      have below' : j.val < 15 := by scalar_tac
      step as ⟨ p, h_p ⟩
      obtain ⟨p', is_p, entry⟩ := entry_v4 j.val below'
      have p_is : p = p' := by simp_all
      subst p_is
      obtain ⟨first, len⟩ := p
      simp only at entry ⊢
      obtain ⟨one_le, le_32, aligned⟩ := prefixes_v4 _ (List.mem_of_getElem? entry)
      simp only at one_le le_32 aligned
      -- the number is xor-ed with the first address and shifted right: zero when it is in the prefix
      step as ⟨ i2, h2 ⟩
      step as ⟨ i3, h3 ⟩
      step as ⟨ i4, h4 ⟩
      have found : i4 = 0#u32 ↔ InPrefix 32 a.val first.val len.val := by
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
        have not_hit : ¬ InPrefix 32 a.val first.val len.val := fun hit => miss (found.mpr hit)
        refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        rw [← same, drop_step _ _ _ _ entry, h5]
        simp [not_hit]
    -- the table is at its end: nothing is left to hold
    · have at_end : j.val = 15 := by scalar_tac
      simp only [below, ite_false]
      refine (WP.spec_ok _).mpr ?_
      rw [at_end] at same
      have none : ¬ ∃ q ∈ LocalV4.drop 15, InPrefix 32 a.val q.1 q.2 := by simp [LocalV4]
      exact ⟨fun h => Bool.noConfusion h, fun found => absurd (same.mpr found) none⟩
  · exact ⟨inside, Iff.rfl⟩

/-- `local_number_v4` says `true` exactly when the number is local. -/
@[step]
theorem local_number_v4_is (a : Std.U32) :
    local_number_v4 a ⦃ r => r = true ↔ IsLocalV4 a.val ⦄ := by
  unfold local_number_v4 IsLocalV4
  exact local_number_v4_loop_is a 0#usize (by scalar_tac)

/-- `local_v4` returns, and says `true` exactly when the number of the 4 bytes is local. -/
@[step]
theorem local_v4_is (a : Std.Array Std.U8 4#usize) :
    local_v4 a ⦃ r => r = true ↔ IsLocalV4 (Number a.val) ⦄ := by
  unfold local_v4
  step as ⟨ n, h_n ⟩
  step as ⟨ r, h_r ⟩
  rw [h_r, h_n]

end AddrCore
