-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: `validate` (crates/idmap-core) follows its specification: it accepts a
-- list of entries exactly when the list is `Valid` (Spec.lean).  `validate` has two loops: the
-- first looks at each entry alone (not empty, not past the limit), the second compares each entry
-- with those before it (an inner loop).  Each loop keeps the same fact: "the answer is `Ok` exactly
-- when the answer it started with was, and what it has read so far is good".
--
-- Why it is needed: this is the proof that `validate` refuses nothing it should accept and
-- accepts nothing it should refuse, and that no sum in it overflows (the entries are 32 bit
-- numbers, the sums are in 64 bits).
--
-- Read before this file: Spec.lean (`Sane`, `Apart`, `Valid`), Ranges.lean, Lists.lean.
--
-- Notation: `x ⦃ r => P r ⦄` is "the function returns, and its result `r` satisfies `P r`";
-- `loop.spec_decr_nat` proves a fact of a loop from a fact that each turn keeps (the invariant)
-- and a number that goes down at each turn; `step as ⟨ x, hx ⟩` runs one Rust line and names its
-- result `x` and what is known of it `hx`; `split` makes one case of each `if`;
-- `scalar_tac` and `omega` decide facts about machine integers and natural numbers.
import IdmapCore.Spec
import IdmapCore.Limits
import IdmapCore.Lists
import IdmapCore.Ranges

open Aeneas Aeneas.Std Result velarx_idmap_core

namespace IdmapCore

/-- The first loop of `validate`: it reads each entry alone.  Started from an answer `res0`, it
ends with `Ok` exactly when `res0` is `Ok` and every entry is sane. -/
theorem validate_checks_each_entry (maps : Slice Map) (res0 : core.result.Result Unit Fault) :
    validate_loop0 maps res0 0#usize ⦃ r =>
      (r = core.result.Result.Ok () ↔
        (res0 = core.result.Result.Ok () ∧ ∀ e ∈ maps.val, Sane e)) ⦄ := by
  unfold validate_loop0
  apply loop.spec_decr_nat (fun q => maps.length - q.2.val)
    (fun q => q.2.val ≤ maps.length ∧
      (q.1 = core.result.Result.Ok () ↔
        (res0 = core.result.Result.Ok () ∧ ∀ e ∈ maps.val.take q.2.val, Sane e)))
  · rintro ⟨res, i⟩ ⟨bound, ok_iff⟩
    simp only at bound ok_iff ⊢
    unfold validate_loop0.body
    dsimp only [Slice.len]
    split
    · rename_i inside
      have inside : i.val < maps.length := by scalar_tac
      have next_entries := all_of_take_one_more maps.val i.val inside Sane
      cases res with
      | Err fault =>
        -- an entry was refused before: the loop stops, and the answer stays a refusal
        simp only [Std.bind_ok, Std.uncurry_apply_pair, Bool.false_eq_true, ↓reduceIte]
        refine (WP.spec_ok _).mpr ?_
        simp only [reduceCtorEq, false_iff, not_and]
        intro res0_ok all
        have both := ok_iff.mpr ⟨res0_ok, fun e e_in => all e (List.mem_of_mem_take e_in)⟩
        exact absurd both (by simp)
      | Ok u =>
        simp only [Std.bind_ok, Std.lift, Std.uncurry_apply_pair, ↓reduceIte]
        step as ⟨ m, hm ⟩
        have hc := core.convert.num.FromU64U32.from_val_eq m.container_id
        have hs := core.convert.num.FromU64U32.from_val_eq m.size
        have hp := core.convert.num.FromU64U32.from_val_eq m.parent_id
        split
        · -- the entry is empty
          rename_i empty
          have empty : m.size.val = 0 := by simpa using congrArg UScalar.val empty
          simp only [Std.bind_ok]
          step as ⟨ i2, hi2 ⟩
          refine ⟨by omega, ?_, by omega⟩
          simp only [reduceCtorEq, false_iff, not_and]
          intro _ all
          rw [hi2] at all
          have sane := (next_entries.mp all).2
          rw [← hm] at sane
          have := sane.1
          omega
        · rename_i has_bytes
          have has_bytes : 0 < m.size.val := by
            have : m.size.val ≠ 0 := fun zero => has_bytes (UScalar.eq_of_val_eq zero)
            omega
          step as ⟨ i2, hi2 ⟩
          rw [id_limit_is_the_largest_u32]
          simp only [Std.bind_ok]
          split
          · -- the container ids end past the limit
            rename_i past
            have past : 4294967295 < m.container_id.val + m.size.val := by scalar_tac
            simp only [Std.bind_ok]
            step as ⟨ i3, hi3 ⟩
            refine ⟨by omega, ?_, by omega⟩
            simp only [reduceCtorEq, false_iff, not_and]
            intro _ all
            rw [hi3] at all
            have sane := (next_entries.mp all).2
            rw [← hm] at sane
            have := sane.2.1
            unfold IdLimit at this
            omega
          · rename_i below
            have below : m.container_id.val + m.size.val ≤ 4294967295 := by scalar_tac
            step as ⟨ i3, hi3 ⟩
            split
            · -- the parent ids end past the limit
              rename_i past
              have past : 4294967295 < m.parent_id.val + m.size.val := by scalar_tac
              simp only [Std.bind_ok]
              step as ⟨ i4, hi4 ⟩
              refine ⟨by omega, ?_, by omega⟩
              simp only [reduceCtorEq, false_iff, not_and]
              intro _ all
              rw [hi4] at all
              have sane := (next_entries.mp all).2
              rw [← hm] at sane
              have := sane.2.2
              unfold IdLimit at this
              omega
            · rename_i below_too
              have below_too : m.parent_id.val + m.size.val ≤ 4294967295 := by scalar_tac
              simp only [Std.bind_ok]
              step as ⟨ i4, hi4 ⟩
              refine ⟨by omega, ?_, by omega⟩
              simp only [true_iff]
              obtain ⟨res0_ok, before⟩ := ok_iff.mp rfl
              rw [hi4]
              refine ⟨res0_ok, next_entries.mpr ⟨before, ?_⟩⟩
              rw [← hm]
              exact ⟨has_bytes, below, below_too⟩
    · -- every entry was read
      rename_i outside
      have : i.val = maps.length := by scalar_tac
      refine (WP.spec_ok _).mpr ?_
      rw [this, List.take_length] at ok_iff
      exact ok_iff
  · exact ⟨by simp, by simp⟩

/-- The inner loop of the second loop of `validate`: it compares the entry `i` (`a`, as `ac`, `ah`
and `asz`) with each of the entries before it, and ends with `Ok` exactly when the answer it
started with was `Ok` and the entry is apart from each of them. -/
theorem validate_compares_an_entry_with_those_before (maps : Slice Map)
    (res0 : core.result.Result Unit Fault) (i : Usize) (ac ah asz : U64)
    (all_have_ids : ∀ e ∈ maps.val, 0 < e.size.val) (inside : i.val < maps.length)
    (is_ac : ac.val = maps.val[i.val].container_id.val)
    (is_ah : ah.val = maps.val[i.val].parent_id.val)
    (is_asz : asz.val = maps.val[i.val].size.val) :
    validate_loop1_loop0 maps res0 i ac ah asz 0#usize ⦃ r =>
      (r = core.result.Result.Ok () ↔
        (res0 = core.result.Result.Ok () ∧
          ∀ e ∈ maps.val.take i.val, Apart e maps.val[i.val])) ⦄ := by
  unfold validate_loop1_loop0
  apply loop.spec_decr_nat (fun q => i.val - q.2.val)
    (fun q => q.2.val ≤ i.val ∧
      (q.1 = core.result.Result.Ok () ↔
        (res0 = core.result.Result.Ok () ∧ ∀ e ∈ maps.val.take q.2.val, Apart e maps.val[i.val])))
  · rintro ⟨res, j⟩ ⟨bound, ok_iff⟩
    simp only at bound ok_iff ⊢
    unfold validate_loop1_loop0.body
    split
    · rename_i before
      have before : j.val < i.val := by scalar_tac
      have inside_j : j.val < maps.length := by omega
      have next_entries := all_of_take_one_more maps.val j.val inside_j
        (fun e => Apart e maps.val[i.val])
      cases res with
      | Err fault =>
        simp only [Std.bind_ok, Std.uncurry_apply_pair, Bool.false_eq_true, ↓reduceIte]
        refine (WP.spec_ok _).mpr ?_
        simp only [reduceCtorEq, false_iff, not_and]
        intro res0_ok all
        have both := ok_iff.mpr ⟨res0_ok, fun e e_in =>
          all e (mem_take_of_le maps.val j.val i.val bound e e_in)⟩
        exact absurd both (by simp)
      | Ok u =>
        simp only [Std.bind_ok, Std.lift, Std.uncurry_apply_pair, ↓reduceIte]
        step as ⟨ b, hb ⟩
        have hc := core.convert.num.FromU64U32.from_val_eq b.container_id
        have hs := core.convert.num.FromU64U32.from_val_eq b.size
        have hp := core.convert.num.FromU64U32.from_val_eq b.parent_id
        have b_has_ids : 0 < b.size.val := all_have_ids b (by rw [hb]; exact List.getElem_mem _)
        have a_has_ids : 0 < maps.val[i.val].size.val :=
          all_have_ids _ (List.getElem_mem _)
        have apart_iff := apart_iff_no_overlap b maps.val[i.val] a_has_ids b_has_ids
        step as ⟨ i1, hi1 ⟩
        -- the entries are compared: `Apart` is that neither the container ids nor the parent ids
        -- overlap
        refine WP.spec_bind (Pₘ := fun res2 =>
          (res2 = core.result.Result.Ok () ↔ Apart b maps.val[i.val])) ?_ ?_
        · have refused : ∀ fault : Fault,
              ((maps.val[i.val].container_id.val < b.container_id.val + b.size.val ∧
                b.container_id.val < maps.val[i.val].container_id.val + maps.val[i.val].size.val) ∨
              (maps.val[i.val].parent_id.val < b.parent_id.val + b.size.val ∧
                b.parent_id.val < maps.val[i.val].parent_id.val + maps.val[i.val].size.val)) →
              ((core.result.Result.Err fault : core.result.Result Unit Fault) =
                  core.result.Result.Ok () ↔ Apart b maps.val[i.val]) := by
            intro fault overlap
            simp only [reduceCtorEq, false_iff]
            intro apart
            have := apart_iff.mp apart
            omega
          have accepted :
              ¬ (maps.val[i.val].container_id.val < b.container_id.val + b.size.val ∧
                b.container_id.val < maps.val[i.val].container_id.val + maps.val[i.val].size.val) →
              ¬ (maps.val[i.val].parent_id.val < b.parent_id.val + b.size.val ∧
                b.parent_id.val < maps.val[i.val].parent_id.val + maps.val[i.val].size.val) →
              ((core.result.Result.Ok () : core.result.Result Unit Fault) =
                  core.result.Result.Ok () ↔ Apart b maps.val[i.val]) := by
            intro no_container no_parent
            simp only [true_iff]
            exact apart_iff.mpr ⟨no_container, no_parent⟩
          split
          · rename_i container_starts_before_b_ends
            have container_starts_before_b_ends : ac.val < i1.val := by scalar_tac
            step as ⟨ i2, hi2 ⟩
            split
            · -- the container ids overlap
              rename_i b_starts_before_a_ends
              have : (core.convert.num.FromU64U32.from b.container_id).val < i2.val := by
                scalar_tac
              exact (WP.spec_ok _).mpr (refused _ (Or.inl (by omega)))
            · rename_i b_starts_after_a_ends
              have : i2.val ≤ (core.convert.num.FromU64U32.from b.container_id).val := by
                scalar_tac
              step as ⟨ i3, hi3 ⟩
              split
              · rename_i parent_starts_before_b_ends
                have : ah.val < i3.val := by scalar_tac
                step as ⟨ i4, hi4 ⟩
                split
                · -- the parent ids overlap
                  rename_i b_parent_starts_before_a_ends
                  have : (core.convert.num.FromU64U32.from b.parent_id).val < i4.val := by
                    scalar_tac
                  exact (WP.spec_ok _).mpr (refused _ (Or.inr (by omega)))
                · rename_i b_parent_starts_after_a_ends
                  have : i4.val ≤ (core.convert.num.FromU64U32.from b.parent_id).val := by
                    scalar_tac
                  exact (WP.spec_ok _).mpr (accepted (by omega) (by omega))
              · rename_i parent_starts_after_b_ends
                have : i3.val ≤ ah.val := by scalar_tac
                exact (WP.spec_ok _).mpr (accepted (by omega) (by omega))
          · rename_i container_starts_after_b_ends
            have : i1.val ≤ ac.val := by scalar_tac
            step as ⟨ i2, hi2 ⟩
            split
            · rename_i parent_starts_before_b_ends
              have : ah.val < i2.val := by scalar_tac
              step as ⟨ i3, hi3 ⟩
              split
              · -- the parent ids overlap
                rename_i b_parent_starts_before_a_ends
                have : (core.convert.num.FromU64U32.from b.parent_id).val < i3.val := by
                  scalar_tac
                exact (WP.spec_ok _).mpr (refused _ (Or.inr (by omega)))
              · rename_i b_parent_starts_after_a_ends
                have : i3.val ≤ (core.convert.num.FromU64U32.from b.parent_id).val := by
                  scalar_tac
                exact (WP.spec_ok _).mpr (accepted (by omega) (by omega))
            · rename_i parent_starts_after_b_ends
              have : i2.val ≤ ah.val := by scalar_tac
              exact (WP.spec_ok _).mpr (accepted (by omega) (by omega))
        · -- the next turn: the entries up to `j` are compared
          intro res2 compared
          step as ⟨ j1, hj1 ⟩
          refine ⟨by omega, ?_, by omega⟩
          rw [hj1, next_entries, compared, ← hb]
          obtain ⟨res0_ok, before_apart⟩ := ok_iff.mp rfl
          constructor
          · intro apart
            exact ⟨res0_ok, before_apart, apart⟩
          · rintro ⟨_, _, apart⟩
            exact apart
    · -- every earlier entry was compared
      rename_i not_before
      have : j.val = i.val := by scalar_tac
      refine (WP.spec_ok _).mpr ?_
      rw [this] at ok_iff
      exact ok_iff
  · exact ⟨by simp, by simp⟩

/-- The second loop of `validate`: it compares each entry with those before it, and ends with
`Ok` exactly when the answer it started with was `Ok` and every two entries are apart. -/
theorem validate_compares_every_pair (maps : Slice Map)
    (res0 : core.result.Result Unit Fault)
    (all_have_ids : res0 = core.result.Result.Ok () → ∀ e ∈ maps.val, 0 < e.size.val) :
    validate_loop1 maps res0 0#usize ⦃ r =>
      (r = core.result.Result.Ok () ↔
        (res0 = core.result.Result.Ok () ∧ maps.val.Pairwise Apart)) ⦄ := by
  unfold validate_loop1
  apply loop.spec_decr_nat (fun q => maps.length - q.2.val)
    (fun q => q.2.val ≤ maps.length ∧
      (q.1 = core.result.Result.Ok () ↔
        (res0 = core.result.Result.Ok () ∧ (maps.val.take q.2.val).Pairwise Apart)))
  · rintro ⟨res, i⟩ ⟨bound, ok_iff⟩
    simp only at bound ok_iff ⊢
    unfold validate_loop1.body
    dsimp only [Slice.len]
    split
    · rename_i inside
      have inside : i.val < maps.length := by scalar_tac
      have next_entries := pairwise_of_take_one_more maps.val i.val inside Apart
      cases res with
      | Err fault =>
        simp only [Std.bind_ok, Std.uncurry_apply_pair, Bool.false_eq_true, ↓reduceIte]
        refine (WP.spec_ok _).mpr ?_
        simp only [reduceCtorEq, false_iff, not_and]
        intro res0_ok all
        have both := ok_iff.mpr ⟨res0_ok, List.Pairwise.sublist (List.take_sublist _ _) all⟩
        exact absurd both (by simp)
      | Ok u =>
        simp only [Std.bind_ok, Std.lift, Std.uncurry_apply_pair, ↓reduceIte]
        obtain ⟨res0_ok, before_apart⟩ := ok_iff.mp rfl
        have all_have_ids := all_have_ids res0_ok
        step as ⟨ a, ha ⟩
        have hc := core.convert.num.FromU64U32.from_val_eq a.container_id
        have hs := core.convert.num.FromU64U32.from_val_eq a.size
        have hp := core.convert.num.FromU64U32.from_val_eq a.parent_id
        step with validate_compares_an_entry_with_those_before maps (core.result.Result.Ok ())
          i _ _ _ all_have_ids inside (by rw [← ha]; exact hc) (by rw [← ha]; exact hp)
          (by rw [← ha]; exact hs) as ⟨ res2, compared ⟩
        step as ⟨ i2, hi2 ⟩
        refine ⟨by omega, ?_, by omega⟩
        rw [hi2, next_entries, compared]
        constructor
        · intro apart
          exact ⟨res0_ok, before_apart, apart⟩
        · rintro ⟨_, _, apart⟩
          exact apart
    · -- every entry was compared
      rename_i outside
      have : i.val = maps.length := by scalar_tac
      refine (WP.spec_ok _).mpr ?_
      rw [this, List.take_length] at ok_iff
      exact ok_iff
  · exact ⟨by simp, by simp⟩

/-- Every entry of a list of sane entries has ids (it is not empty). -/
theorem sane_entries_have_ids (entries : List Map) (all_sane : ∀ e ∈ entries, Sane e) :
    ∀ e ∈ entries, 0 < e.size.val :=
  fun e e_in => (all_sane e e_in).1

/-- **`validate` accepts exactly the valid lists**: it returns, and its answer is `Ok` exactly
when the list is `Valid`. -/
theorem validate_accepts_exactly_the_valid_lists (maps : Slice Map) :
    validate maps ⦃ r => (r = core.result.Result.Ok () ↔ Valid maps.val) ⦄ := by
  unfold validate
  dsimp only [Slice.len]
  split
  · -- too many entries
    rename_i too_many
    have too_many : maps.length > 340 := by
      have := max_extents_is_340
      scalar_tac
    refine (WP.spec_ok _).mpr ?_
    simp only [reduceCtorEq, false_iff]
    intro valid
    have := valid.1
    unfold ExtentLimit at this
    have same : maps.length = maps.val.length := rfl
    omega
  · rename_i few
    have few : maps.length ≤ 340 := by
      have := max_extents_is_340
      scalar_tac
    step with validate_checks_each_entry maps (core.result.Result.Ok ()) as ⟨ res, each_entry ⟩
    step with validate_compares_every_pair maps res (fun res_ok => by
      exact sane_entries_have_ids _ (each_entry.mp res_ok)) as ⟨ answer, every_pair ⟩
    rw [every_pair, each_entry]
    unfold Valid ExtentLimit
    have same : maps.length = maps.val.length := rfl
    constructor
    · rintro ⟨sane, apart⟩
      exact ⟨by omega, sane, apart⟩
    · rintro ⟨_, sane, apart⟩
      exact ⟨sane, apart⟩

end IdmapCore
