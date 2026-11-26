-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `passwd_line` and `group_line` answer: a line cut at its colons is an entry.
-- Why it is needed: the entries `passwd_find` and `group_gid` return are made by them.
-- Read before this file: Colons.lean.
-- Notation: `f x ⦃ r => P r ⦄` is "the Rust `f` returns on `x`, with no panic and no endless loop,
--    and its answer `r` satisfies `P`"; `step` goes through one line of the Rust function and
--    `scalar_tac` proves a fact about machine numbers by arithmetic; `↑x` is the number a
--    machine integer is.
import UserCore.Colons
open Aeneas Aeneas.Std Result velarx_user_core
namespace UserCore

/-- A place is among the colons when it is in the range and its byte is a colon. -/
theorem mem_colons (d : List Std.U8) (start stop x : Nat) :
    x ∈ Colons d start stop ↔ start ≤ x ∧ x < stop ∧ ByteAt d x 58 := by
  unfold Colons
  simp only [List.mem_filter, List.mem_range'_1, decide_eq_true_eq]
  constructor
  · rintro ⟨⟨h1, h2⟩, h3⟩; exact ⟨h1, by omega, h3⟩
  · rintro ⟨h1, h2, h3⟩; exact ⟨⟨h1, by omega⟩, h3⟩

/-- The places of the colons are in increasing order. -/
theorem colons_sorted (d : List Std.U8) (start stop : Nat) :
    (Colons d start stop).Pairwise (· < ·) := by
  unfold Colons
  exact List.Pairwise.filter _ (List.pairwise_lt_range' (s := start) (n := stop - start))

/-- The six places of `cut` are the first six colons. -/
theorem colons_six (d : List Std.U8) (start stop : Nat) (cut : Std.Array Std.Usize 6#usize) (n : Std.Usize)
    (h : n.val ≤ 6 ∧ (cut.val.take n.val).map (·.val) = (Colons d start stop).take 6)
    (six : ¬ n < 6#usize) :
    ∃ a0 a1 a2 a3 a4 a5 : Std.Usize, ∃ rest, cut.val = [a0, a1, a2, a3, a4, a5] ∧
      Colons d start stop = a0.val :: a1.val :: a2.val :: a3.val :: a4.val :: a5.val :: rest := by
  have n6 : n.val = 6 := by scalar_tac
  have len : cut.val.length = 6 := by simp
  rw [n6, List.take_of_length_le (l := cut.val) (i := 6) (by omega)] at h
  obtain ⟨_, h⟩ := h
  obtain ⟨a0, a1, a2, a3, a4, a5, hc⟩ : ∃ a0 a1 a2 a3 a4 a5 : Std.Usize,
      cut.val = [a0, a1, a2, a3, a4, a5] := by
    generalize cut.val = L at len
    rcases L with _ | ⟨x0, _ | ⟨x1, _ | ⟨x2, _ | ⟨x3, _ | ⟨x4, _ | ⟨x5, rest⟩⟩⟩⟩⟩⟩ <;>
      first | (simp only [List.length_cons, List.length_nil] at len; omega) |
        (simp only [List.length_cons] at len
         have : rest = [] := List.eq_nil_of_length_eq_zero (by omega)
         subst this
         exact ⟨_, _, _, _, _, _, rfl⟩)
  rw [hc] at h
  refine ⟨a0, a1, a2, a3, a4, a5, (Colons d start stop).drop 6, hc, ?_⟩
  conv_lhs => rw [← List.take_append_drop 6 (Colons d start stop)]
  rw [← h]
  rfl

/-- `passwd_line` returns, and an entry it answers is the entry of that line. -/
theorem passwd_line_spec (data : Slice Std.U8) (start stop : Std.Usize)
    (hs : start.val ≤ stop.val) (hstop : stop.val ≤ data.length) :
    passwd_line data start stop ⦃ r =>
      ∀ e, r = some e → IsPasswdEntry data.val start.val stop.val e ⦄ := by
  unfold passwd_line
  step with colons_spec as ⟨ cut, n, hn, hcut ⟩
  split
  · refine (WP.spec_ok _).mpr ?_
    intro e he; cases he
  · rename_i six
    obtain ⟨a0, a1, a2, a3, a4, a5, rest, hc, hL⟩ :=
      colons_six data.val start.val stop.val cut n ⟨hn, hcut⟩ six
    have sorted := colons_sorted data.val start.val stop.val
    have inside : ∀ x ∈ Colons data.val start.val stop.val, x < stop.val := fun x hx => ((mem_colons _ _ _ _).mp hx).2.1
    rw [hL] at sorted inside
    simp only [List.pairwise_cons, List.mem_cons] at sorted
    have idx : ∀ k : Std.Usize, ∀ a : Std.Usize, cut.val[k.val]? = some a → Array.index_usize cut k = ok a := by
      intro k a h
      simp [Array.index_usize, h]
    have e0 := idx 0#usize a0 (by simp [hc])
    have e1 := idx 1#usize a1 (by simp [hc])
    have e2 := idx 2#usize a2 (by simp [hc])
    have e3 := idx 3#usize a3 (by simp [hc])
    have e4 := idx 4#usize a4 (by simp [hc])
    have e5 := idx 5#usize a5 (by simp [hc])
    simp only [e0, e1, e2, e3, e4, e5, bind_ok]
    obtain ⟨lt01, lt12, lt23, lt34, lt45⟩ : a0.val < a1.val ∧ a1.val < a2.val ∧ a2.val < a3.val ∧
        a3.val < a4.val ∧ a4.val < a5.val := by
      refine ⟨sorted.1 _ (by simp), sorted.2.1 _ (by simp), sorted.2.2.1 _ (by simp),
        sorted.2.2.2.1 _ (by simp), sorted.2.2.2.2.1 _ (by simp)⟩
    have below := inside a5.val (by simp)
    have below3 := inside a3.val (by simp)
    have below2 := inside a2.val (by simp)
    step as ⟨ i1, i1_post ⟩
    step as ⟨ s, s_post, s_len ⟩
    step with (parse_id_spec s) as ⟨ uid, uid_post ⟩
    step as ⟨ i3, i3_post ⟩
    step as ⟨ s1, s1_post, s1_len ⟩
    step with (parse_id_spec s1) as ⟨ gid, gid_post ⟩
    rcases uid with _ | uid1
    · refine (WP.spec_ok _).mpr ?_
      intro e he; cases he
    rcases gid with _ | gid1
    · refine (WP.spec_ok _).mpr ?_
      intro e he; cases he
    step as ⟨ i6, i6_post ⟩
    step as ⟨ i8, i8_post ⟩
    intro e he
    cases he
    refine ⟨a0.val, a1.val, a2.val, a3.val, a4.val, a5.val, rest, hL, rfl, rfl, ?_, ?_, ?_, rfl, ?_, rfl⟩
    · have h := (uid_post uid1).mp rfl
      rw [s_post, i1_post] at h; exact h
    · have h := (gid_post gid1).mp rfl
      rw [s1_post, i3_post] at h; exact h
    · show i6.val = _; omega
    · show i8.val = _; omega

/-- What `colons` answers when it found at least three colons. -/
theorem colons_three (d : List Std.U8) (start stop : Nat) (cut : Std.Array Std.Usize 6#usize)
    (n : Std.Usize)
    (h : n.val ≤ 6 ∧ (cut.val.take n.val).map (·.val) = (Colons d start stop).take 6)
    (enough : ¬ n < 3#usize) :
    ∃ a0 a1 a2 : Std.Usize, ∃ rest, Colons d start stop = a0.val :: a1.val :: a2.val :: rest ∧
      cut.val[0]? = some a0 ∧ cut.val[1]? = some a1 ∧ cut.val[2]? = some a2 ∧
      (3 < n.val → ∃ a3, cut.val[3]? = some a3 ∧ rest.head? = some a3.val) ∧
      (¬ 3 < n.val → rest = []) := by
  obtain ⟨hn, h⟩ := h
  have len : cut.val.length = 6 := by simp
  have hl : n.val = min 6 (Colons d start stop).length := by
    have := congrArg List.length h
    simp only [List.length_map, List.length_take] at this
    omega
  have get : ∀ k, k < n.val → ∃ a : Std.Usize, cut.val[k]? = some a ∧
      (Colons d start stop)[k]? = some a.val := by
    intro k hk
    have := congrArg (fun l => l[k]?) h
    simp only [List.getElem?_map, List.getElem?_take, hk, ite_true] at this
    have hk6 : k < cut.val.length := by omega
    refine ⟨cut.val[k], List.getElem?_eq_getElem hk6, ?_⟩
    rw [List.getElem?_eq_getElem hk6] at this
    exact (by simpa using this.symm : _ ∧ _).2
  have n3 : 3 ≤ n.val := by scalar_tac
  obtain ⟨a0, c0, d0⟩ := get 0 (by omega)
  obtain ⟨a1, c1, d1⟩ := get 1 (by omega)
  obtain ⟨a2, c2, d2⟩ := get 2 (by omega)
  have len3 : 3 ≤ (Colons d start stop).length := by omega
  obtain ⟨rest, hrest⟩ : ∃ rest, Colons d start stop = a0.val :: a1.val :: a2.val :: rest := by
    generalize hC : Colons d start stop = L at len3 d0 d1 d2
    rcases L with _ | ⟨x0, _ | ⟨x1, _ | ⟨x2, rest⟩⟩⟩
    · simp at len3
    · simp at len3
    · simp at len3
    · simp only [List.getElem?_cons_zero, Option.some.injEq] at d0
      simp only [List.getElem?_cons_succ, List.getElem?_cons_zero, Option.some.injEq] at d1 d2
      exact ⟨rest, by rw [d0, d1, d2]⟩
  refine ⟨a0, a1, a2, rest, hrest, c0, c1, c2, ?_, ?_⟩
  · intro big
    obtain ⟨a3, c3, d3⟩ := get 3 big
    refine ⟨a3, c3, ?_⟩
    rw [hrest] at d3
    simpa [List.head?_eq_getElem?] using d3
  · intro small
    rw [hrest] at hl
    simp only [List.length_cons] at hl
    have : rest.length = 0 := by omega
    exact List.eq_nil_of_length_eq_zero this

/-- What `group_line` does after the comment test: it returns, and a line it answers has its name, gid and members between the colons. -/
theorem group_tail_spec (data : Slice Std.U8) (start stop : Std.Usize)
    (hs : start.val ≤ stop.val) (hstop : stop.val ≤ data.length) :
    (do
      let (cut, n) ← colons data start stop
      if n < 3#usize then ok none
        else do
          let i1 ← cut.index_usize 1#usize
          let i2 ← i1 + 1#usize
          let i3 ← cut.index_usize 2#usize
          let s ← core.slice.index.SliceIndexRangeUsizeSlice.index { start := i2, «end» := i3 } data
          let o ← parse_id s
          let cf ← core.option.Option.Insts.CoreOpsTry_traitTry.branch o
          match cf with
            | core.ops.control_flow.ControlFlow.Continue val => do
              let members_end ← if n > 3#usize then cut.index_usize 3#usize else ok stop
              let i4 ← cut.index_usize 0#usize
              let i5 ← i3 + 1#usize
              ok (some ({ «name» := (start, i4), gid := val, members := (i5, members_end) } : GroupLine))
            | core.ops.control_flow.ControlFlow.Break residual =>
              core.option.Option.Insts.CoreOpsTry_traitFromResidualOptionNever.from_residual GroupLine residual)
      ⦃ r => ∀ g : GroupLine, r = some g → GroupColons data.val start.val stop.val g ⦄ := by
  step with colons_spec as ⟨ cut, n, hn, hcut ⟩
  split
  · refine (WP.spec_ok _).mpr ?_
    intro g hg; cases hg
  · rename_i enough
    obtain ⟨a0, a1, a2, rest, hL, c0, c1, c2, c3, c4⟩ := colons_three _ _ _ cut n ⟨hn, hcut⟩ enough
    have sorted := colons_sorted data.val start.val stop.val
    have inside : ∀ x ∈ Colons data.val start.val stop.val, x < stop.val := fun x hx => ((mem_colons _ _ _ _).mp hx).2.1
    rw [hL] at sorted inside
    simp only [List.pairwise_cons, List.mem_cons] at sorted
    have idx : ∀ k : Std.Usize, ∀ a : Std.Usize, cut.val[k.val]? = some a → Array.index_usize cut k = ok a := by
      intro k a h
      simp [Array.index_usize, h]
    have lt01 : a0.val < a1.val := sorted.1 _ (by simp)
    have lt12 : a1.val < a2.val := sorted.2.1 _ (by simp)
    have below2 := inside a2.val (by simp)
    simp only [idx 0#usize a0 c0, idx 1#usize a1 c1, idx 2#usize a2 c2, bind_ok]
    step as ⟨ i2, i2_post ⟩
    step as ⟨ s, s_post, s_len ⟩
    step with (parse_id_spec s) as ⟨ o, o_post ⟩
    rcases o with _ | gid
    · simp only [core.option.Option.Insts.CoreOpsTry_traitTry.branch, bind_ok,
        core.option.Option.Insts.CoreOpsTry_traitFromResidualOptionNever.from_residual]
      refine (WP.spec_ok _).mpr ?_
      intro g hg; cases hg
    · simp only [core.option.Option.Insts.CoreOpsTry_traitTry.branch, bind_ok]
      by_cases big : n > 3#usize
      · have big' : 3 < n.val := by scalar_tac
        obtain ⟨a3, d3, d3'⟩ := c3 big'
        simp only [big, ite_true, idx 3#usize a3 d3, bind_ok]
        step as ⟨ i5, i5_post ⟩
        intro g hg
        cases hg
        refine ⟨a0.val, a1.val, a2.val, rest, hL, rfl, rfl, ?_, ?_, ?_⟩
        · have h := (o_post gid).mp rfl
          rw [s_post, i2_post] at h; exact h
        · show i5.val = _; omega
        · simp [d3']
      · have small : ¬ 3 < n.val := by intro h; apply big; scalar_tac
        have nil := c4 small
        simp only [big, ite_false, bind_ok]
        step as ⟨ i5, i5_post ⟩
        intro g hg
        cases hg
        refine ⟨a0.val, a1.val, a2.val, rest, hL, rfl, rfl, ?_, ?_, ?_⟩
        · have h := (o_post gid).mp rfl
          rw [s_post, i2_post] at h; exact h
        · show i5.val = _; omega
        · simp [nil]

/-- `group_line` returns, and a line it answers is the group line of that text: not a comment, with the colons. -/
theorem group_line_spec (data : Slice Std.U8) (start stop : Std.Usize)
    (hs : start.val ≤ stop.val) (hstop : stop.val ≤ data.length) :
    group_line data start stop ⦃ r =>
      ∀ g, r = some g → IsGroupEntry data.val start.val stop.val g ⦄ := by
  unfold group_line
  split
  · rename_i inside
    step as ⟨ i, i_post ⟩
    split
    · refine (WP.spec_ok _).mpr ?_
      intro g hg; cases hg
    · rename_i not_hash
      have below : start.val < stop.val := by scalar_tac
      have byte : data.val[start.val]? = some i := by rw [i_post]; simp at *
      refine WP.spec_mono (group_tail_spec data start stop hs hstop) ?_
      intro r h g hg
      refine ⟨?_, h g hg⟩
      rintro ⟨_, is35⟩
      rw [byteAt_iff _ _ _ byte] at is35
      apply not_hash; scalar_tac
  · rename_i outside
    refine WP.spec_mono (group_tail_spec data start stop hs hstop) ?_
    intro r h g hg
    refine ⟨?_, h g hg⟩
    rintro ⟨below, _⟩
    apply outside; scalar_tac

end UserCore
