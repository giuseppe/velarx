-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: the first two loops of `plan` (crates/plan-core): the two tables `home`
-- and `slot` are made, one entry per content, and `home` gets, for each content some layer has,
-- the first layer that has it.  Also the small facts about reading a list of tables in order
-- (`Before`, `Seen`) that the later files use for every pass over the layers.
--
-- Why it is needed: the claims of Spec.lean are about the groups, but the code decides where a
-- content goes by looking it up in `home`; this file says what `home` holds after each file read
-- (`HomeTable`), the invariant of the loops, in words at each definition.
--
-- Read before this file: Spec.lean, and `plan` of src/lib.rs.
--
-- Notation: `plan_loop1_loop0 ... ⦃ r => P r ⦄` is "the loop returns, and its result `r`
-- satisfies `P r`" (as in Spec.lean); `step as ⟨ x, hx ⟩` runs one Rust line and names its
-- result `x` and what is known of it `hx`; `v.val` is the list inside a vector; `l[i]?` is the
-- element `i` of a list if there is one.
import PlanCore.Spec

open Aeneas Aeneas.Std Result velarx_plan_core

namespace PlanCore

/-- A `u32` keeps its value as an index. -/
@[step]
theorem index_of_u32 (x : Std.U32) :
    lift (UScalar.cast .Usize x) ⦃ r => r.val = x.val ⦄ := by
  simp only [lift, Std.WP.spec_ok, UScalar.cast_val_eq]
  exact Nat.mod_eq_of_lt (by scalar_tac)

/-- Looking layer `l` up in `layers` (a cast of its number, then an index) finds its table. -/
theorem layer_bind {layers : Slice (alloc.vec.Vec File)} {l : Std.U32}
    {table : alloc.vec.Vec File} (table_is : layers.val[l.val]? = some table)
    {β : Type} (k : alloc.vec.Vec File → Result β) :
    (do let i ← lift (UScalar.cast .Usize l)
        let v ← layers.index_usize i
        k v) = k table := by
  have lt : l.val < layers.length := (List.getElem?_eq_some_iff.mp table_is).1
  have cast : (UScalar.cast .Usize l).val = l.val := by
    simp only [UScalar.cast_val_eq]
    exact Nat.mod_eq_of_lt (by scalar_tac)
  have : layers.val[(UScalar.cast .Usize l).val]? = some table := by rw [cast]; exact table_is
  simp only [lift, Std.bind_ok, Slice.index_usize, Slice.getElem?_Usize_eq, this]

/-- `index_mut` of a vector finds the element and a way to write it back: `set`. -/
theorem index_mut_eq {α : Type} (v : alloc.vec.Vec α) (i : Std.Usize)
    (inside : i.val < v.length) :
    v.index_mut_usize i = ok (v.val[i.val], v.set i) := by
  have : v.val[i.val]? = some v.val[i.val] := List.getElem?_eq_getElem inside
  simp [alloc.vec.Vec.index_mut_usize, alloc.vec.Vec.index_usize, this]

/-- Some file before the position (`l`, `f`) (a file of a layer below `l`, or one of
the first `f` of layer `l`) is in layer `k` with content `c`, and `P k c` holds. -/
def Before (layers : Slice (alloc.vec.Vec File)) (l f : Nat)
    (P : Nat → Std.U32 → Prop) : Prop :=
  ∃ k table i file, layers.val[k]? = some table ∧ table.val[i]? = some file ∧
    P k file.content ∧ (k < l ∨ (k = l ∧ i < f))

/-- A file one position on adds that file, and nothing else. -/
theorem before_step {layers : Slice (alloc.vec.Vec File)} {l f : Nat}
    {table : alloc.vec.Vec File} {file : File}
    (table_is : layers.val[l]? = some table) (file_is : table.val[f]? = some file)
    (P : Nat → Std.U32 → Prop) :
    Before layers l (f + 1) P ↔ Before layers l f P ∨ P l file.content := by
  constructor
  · rintro ⟨k, t, i, x, kt, it, hp, hk⟩
    rcases hk with hk | ⟨rfl, hi⟩
    · exact Or.inl ⟨k, t, i, x, kt, it, hp, Or.inl hk⟩
    · by_cases hif : i < f
      · exact Or.inl ⟨k, t, i, x, kt, it, hp, Or.inr ⟨rfl, hif⟩⟩
      · have : i = f := by omega
        subst this
        rw [table_is] at kt
        cases kt
        rw [file_is] at it
        cases it
        exact Or.inr hp
  · rintro (⟨k, t, i, x, kt, it, hp, hk⟩ | hp)
    · refine ⟨k, t, i, x, kt, it, hp, ?_⟩
      rcases hk with hk | ⟨rfl, hi⟩
      · exact Or.inl hk
      · exact Or.inr ⟨rfl, by omega⟩
    · exact ⟨l, table, f, file, table_is, file_is, hp, Or.inr ⟨rfl, by omega⟩⟩

/-- At the end of a layer, the next layer starts: nothing is added. -/
theorem before_next_layer {layers : Slice (alloc.vec.Vec File)} {l : Nat}
    {table : alloc.vec.Vec File} (table_is : layers.val[l]? = some table)
    (P : Nat → Std.U32 → Prop) :
    Before layers (l + 1) 0 P ↔ Before layers l table.length P := by
  constructor
  · rintro ⟨k, t, i, x, kt, it, hp, hk⟩
    refine ⟨k, t, i, x, kt, it, hp, ?_⟩
    rcases hk with hk | ⟨rfl, hi⟩
    · by_cases hkl : k = l
      · subst hkl
        rw [table_is] at kt
        cases kt
        exact Or.inr ⟨rfl, (List.getElem?_eq_some_iff.mp it).1⟩
      · exact Or.inl (by omega)
    · omega
  · rintro ⟨k, t, i, x, kt, it, hp, hk⟩
    refine ⟨k, t, i, x, kt, it, hp, Or.inl ?_⟩
    omega

/-- The content `c` was seen before the position (`l`, `f`). -/
abbrev Seen (layers : Slice (alloc.vec.Vec File)) (l f : Nat) (c : Std.U32) : Prop :=
  Before layers l f (fun _ c' => c' = c)

/-- Layer `k` is the first that has `c`. -/
def First (layers : Slice (alloc.vec.Vec File)) (k : Nat) (c : Std.U32) : Prop :=
  Has layers k c ∧ ∀ j < k, ¬ Has layers j c

/-- What `home` says once the files before (`l`, `f`) were read: a content not seen is
`none`; a content seen is `some` of the first layer that has it. -/
def HomeTable (layers : Slice (alloc.vec.Vec File)) (l f : Nat)
    (home : alloc.vec.Vec (Option (Std.U32 × Std.U64))) : Prop :=
  ∀ c : Std.U32, c.val < home.length →
    (home.val[c.val]? = some none ↔ ¬ Seen layers l f c) ∧
    ∀ k s, home.val[c.val]? = some (some (k, s)) → First layers k.val c

/-- The first loop of `plan` (`home` and `slot` each get a `None` for every content): from
any point of it, both tables end as `present.length` entries of `none`. -/
@[step]
theorem tables_start (present : Slice Bool)
    (home : alloc.vec.Vec (Option (Std.U32 × Std.U64)))
    (slot : alloc.vec.Vec (Option Std.Usize)) (c : Std.Usize)
    (homes : home.val = List.replicate c.val none) (slots : slot.val = List.replicate c.val none)
    (inside : c.val ≤ present.length) :
    plan_loop0 present home slot c ⦃ r =>
      r.1.val = List.replicate present.length none ∧
      r.2.val = List.replicate present.length none ⦄ := by
  unfold plan_loop0
  apply loop.spec_decr_nat (fun p => present.length - p.2.2.val)
    (fun p => p.1.val = List.replicate p.2.2.val none ∧
      p.2.1.val = List.replicate p.2.2.val none ∧ p.2.2.val ≤ present.length)
  · rintro ⟨home, slot, c⟩ ⟨homes, slots, inside⟩
    simp only at homes slots inside ⊢
    unfold plan_loop0.body
    dsimp only [Slice.len]
    split
    · rename_i below
      step*
      have below : c.val < present.length := by scalar_tac
      refine ⟨?_, ?_, ?_, ?_⟩
      · rw [home1_post, c1_post, homes, List.replicate_succ']
      · rw [slot1_post, c1_post, slots, List.replicate_succ']
      · omega
      · omega
    · rename_i atend
      have : c.val = present.length := by scalar_tac
      simp only [WP.spec_ok, homes, slots, this, and_self]
  · exact ⟨homes, slots, inside⟩

/-- The inner loop of the first pass: the files of layer `l` are read, and each content not
seen before gets that layer as its home. -/
@[step]
theorem homes_of_a_layer (layers : Slice (alloc.vec.Vec File)) (l : Std.U32)
    (table : alloc.vec.Vec File) (table_is : layers.val[l.val]? = some table)
    (home : alloc.vec.Vec (Option (Std.U32 × Std.U64))) (f : Std.Usize)
    (inside : ∀ file ∈ table.val, file.content.val < home.length)
    (read : f.val ≤ table.length) (homes : HomeTable layers l.val f.val home) :
    plan_loop1_loop0 layers home l f ⦃ r =>
      r.length = home.length ∧ HomeTable layers l.val table.length r ⦄ := by
  unfold plan_loop1_loop0
  apply loop.spec_decr_nat (fun p => table.length - p.2.val)
    (fun p => p.1.length = home.length ∧ HomeTable layers l.val p.2.val p.1 ∧
      p.2.val ≤ table.length)
  · rintro ⟨now, f⟩ ⟨same, homes, read⟩
    simp only at same homes read ⊢
    unfold plan_loop1_loop0.body
    -- (the table of layer `l` is found, then the loop asks whether file `f` is still inside it)
    simp only [layer_bind table_is]
    simp only [alloc.vec.Vec.len]
    split
    · rename_i below
      -- the file `f` of the table is read
      have below : f.val < table.length := by scalar_tac
      simp only [alloc.vec.Vec.index_slice_index, alloc.vec.Vec.index_mut_slice_index]
      step as ⟨ file, hfile ⟩
      have file_is : table.val[f.val]? = some file := by
        rw [hfile]; exact List.getElem?_eq_getElem below
      have inside_now : file.content.val < now.length := by
        rw [same]; exact inside file (List.mem_of_getElem? file_is)
      step as ⟨ i3, hi3 ⟩
      step as ⟨ o, ho ⟩
      -- `if home[content].is_none()`: the content was not seen before, so layer `l` is its home
      by_cases unseen : o.isNone = true
      · simp only [unseen, ↓reduceIte]
        step as ⟨ i4, hi4 ⟩
        simp only [index_mut_eq now i4 (by omega), Std.bind_ok]
        step as ⟨ f1, hf1 ⟩
        have mem := List.mem_of_getElem? file_is
        have fresh : now.val[file.content.val]? = some none := by
          rw [ho] at unseen
          have hlen : i3.val < now.val.length := by rw [hi3]; exact inside_now
          have : now.val[i3.val] = none := Option.isNone_iff_eq_none.mp unseen
          rw [← hi3, List.getElem?_eq_getElem hlen, this]
        have unseen_before : ¬ Seen layers l.val f.val file.content :=
          (homes file.content inside_now).1.mp fresh
        refine ⟨by simp [same], ?_, by omega, by omega⟩
        intro c hc
        rw [hf1]
        simp only [alloc.vec.Vec.set_val_eq, alloc.vec.Vec.length, List.length_set] at hc ⊢
        have seen_step : Seen layers l.val (f.val + 1) c ↔
            Seen layers l.val f.val c ∨ file.content = c :=
          before_step table_is file_is (fun _ c' => c' = c)
        by_cases same_content : c = file.content
        · subst same_content
          have written : (now.val.set i4.val (some (l, file.size)))[file.content.val]? =
              some (some (l, file.size)) := by
            rw [hi4]; exact List.getElem?_set_self (by omega)
          rw [written]
          refine ⟨⟨fun h => by simp at h, fun h => (h (seen_step.mpr (Or.inr rfl))).elim⟩, ?_⟩
          intro k s hks
          simp only [Option.some.injEq] at hks
          obtain ⟨rfl, -⟩ := hks
          refine ⟨⟨table, table_is, file, mem, rfl⟩, fun j below hj => ?_⟩
          obtain ⟨t, tj, x, xt, hx⟩ := hj
          obtain ⟨i, hi⟩ := List.mem_iff_getElem?.mp xt
          exact unseen_before ⟨j, t, i, x, tj, hi, hx, Or.inl below⟩
        · have other : (now.val.set i4.val (some (l, file.size)))[c.val]? = now.val[c.val]? := by
            apply List.getElem?_set_ne
            intro h
            apply same_content
            apply UScalar.eq_of_val_eq
            omega
          rw [other]
          have old := homes c (by omega)
          refine ⟨?_, old.2⟩
          rw [old.1, seen_step]
          constructor
          · intro h hc2
            rcases hc2 with hc2 | hc2
            · exact h hc2
            · exact same_content hc2.symm
          · intro h hc2
            exact h (Or.inl hc2)
      -- the content was seen: `home` stays as it is
      · simp only [unseen, Bool.false_eq_true, ↓reduceIte, Std.bind_ok]
        step as ⟨ f1, hf1 ⟩
        refine ⟨same, ?_, by omega, by omega⟩
        intro c hc
        rw [hf1]
        have seen_step : Seen layers l.val (f.val + 1) c ↔
            Seen layers l.val f.val c ∨ file.content = c :=
          before_step table_is file_is (fun _ c' => c' = c)
        have old := homes c hc
        refine ⟨?_, old.2⟩
        rw [old.1, seen_step]
        constructor
        · intro h hc2
          rcases hc2 with hc2 | hc2
          · exact h hc2
          · subst hc2
            have hlen : i3.val < now.val.length := by rw [hi3]; exact inside_now
            have found : now.val[i3.val]? = some o := by
              rw [ho]; exact List.getElem?_eq_getElem hlen
            rw [hi3, old.1.mpr h] at found
            simp only [Option.some.injEq] at found
            exact unseen (by rw [← found]; rfl)
        · intro h hc2
          exact h (Or.inl hc2)
    · have : f.val = table.length := by scalar_tac
      simp only [WP.spec_ok, same, true_and]
      rw [← this]
      exact homes
  · exact ⟨rfl, homes, read⟩

/-- The first pass over all the layers: `home` ends up with the first layer of each content
that some layer has, and `none` for the others. -/
@[step]
theorem homes_of_the_layers (layers : Slice (alloc.vec.Vec File))
    (many : layers.length ≤ Std.U32.max)
    (home : alloc.vec.Vec (Option (Std.U32 × Std.U64))) (l : Std.U32)
    (inside : ∀ table ∈ layers.val, ∀ file ∈ table.val, file.content.val < home.length)
    (read : l.val ≤ layers.length) (homes : HomeTable layers l.val 0 home) :
    plan_loop1 layers home l ⦃ r =>
      r.length = home.length ∧ HomeTable layers layers.length 0 r ⦄ := by
  unfold plan_loop1
  apply loop.spec_decr_nat (fun p => layers.length - p.2.val)
    (fun p => p.1.length = home.length ∧ HomeTable layers p.2.val 0 p.1 ∧
      p.2.val ≤ layers.length)
  · rintro ⟨now, l⟩ ⟨same, homes, read⟩
    simp only at same homes read ⊢
    unfold plan_loop1.body
    step as ⟨ i, hi ⟩
    dsimp only [Slice.len]
    split
    · rename_i below
      have below : l.val < layers.length := by scalar_tac
      obtain ⟨table, table_is⟩ : ∃ table, layers.val[l.val]? = some table :=
        ⟨_, List.getElem?_eq_getElem below⟩
      have table_in := List.mem_of_getElem? table_is
      step as ⟨ made, made_length, made_homes ⟩
      step as ⟨ next, hnext ⟩
      refine ⟨by rw [made_length, same], ?_, by omega, by omega⟩
      rw [hnext]
      simpa only [HomeTable, Seen, before_next_layer table_is] using made_homes
    · have : l.val = layers.length := by scalar_tac
      simp only [WP.spec_ok, same, true_and]
      rw [← this]
      exact homes
  · exact ⟨rfl, homes, read⟩

end PlanCore
