-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what the three small loops of the crate answer: `has_at` (does a slice begin with a word at a
-- place), `has_nul` (does a slice have a zero byte) and `namespace` (the length of the namespace
-- a name begins with, or 0).
-- Why it is needed: `class` is built from these three, so what `class` says about a name is read from what they say
-- about bytes: each is proved, once, to answer as a plain statement about lists.
-- Read before this file: Spec.lean.
-- Notation: `f x ⦃ r => P r ⦄` reads: the Rust function `f`, given `x`, returns and its answer `r` satisfies
-- `P r`.  `a <+: b` says the list `a` is the beginning of `b`.  `step` goes through one line of the
-- Rust function; `scalar_tac` and `omega` prove facts about numbers by arithmetic.
import OverlayCore.Spec
open Aeneas Aeneas.Std Result velarx_overlay_core
namespace OverlayCore

/-- **The loop of `has_at`** from the place `i`, with the flag `flag`: it answers true exactly when the
flag is true and the word agrees with the bytes at `at_ + k` for every `k` from `i` on.  The flag may
be true only when the word fits after `at_` (the loop reads the bytes of the first slice at the
places of the word). -/
theorem has_at_loop_answers (s lit : Slice Std.U8) (at_ : Std.Usize) (flag : Bool) (i : Std.Usize)
    (room : flag = true → at_.val + lit.length ≤ s.length) :
    has_at_loop s at_ lit flag i ⦃ r =>
      r = true ↔ flag = true ∧ ∀ k, i.val ≤ k → k < lit.length → s.val[at_.val + k]? = lit.val[k]? ⦄ := by
  unfold has_at_loop
  -- the loop ends because the word has fewer places left at each round; what stays true at every
  -- round is that the answer so far, with what is left to check, is the answer asked for
  apply loop.spec_decr_nat (fun (q : Bool × Std.Usize) => lit.length - q.2.val)
    (fun (q : Bool × Std.Usize) =>
      (q.1 = true → at_.val + lit.length ≤ s.length) ∧
      ((q.1 = true ∧ ∀ k, q.2.val ≤ k → k < lit.length → s.val[at_.val + k]? = lit.val[k]?) ↔
        (flag = true ∧ ∀ k, i.val ≤ k → k < lit.length → s.val[at_.val + k]? = lit.val[k]?)))
  · rintro ⟨flag', i'⟩ ⟨room', same_answer⟩
    simp only at room' same_answer ⊢
    unfold has_at_loop.body
    by_cases still : flag' = true
    · simp only [still, ite_true]
      by_cases below : i'.val < lit.length
      · -- a place of the word is left: the byte of the slice and the byte of the word are compared
        have below' : i' < Slice.len lit := by scalar_tac
        simp only [below', ite_true]
        have inside : at_.val + i'.val < s.length := by have := room' still; omega
        step as ⟨ i2, is_i2 ⟩
        step as ⟨ x, is_x ⟩
        step as ⟨ y, is_y ⟩
        step as ⟨ i3, is_i3 ⟩
        have at_s : s.val[at_.val + i'.val]? = some x := by
          rw [is_x]; simp [is_i2, inside]
        have at_lit : lit.val[i'.val]? = some y := by
          rw [is_y]; simp [below]
        have next : (∀ k, i'.val ≤ k → k < lit.length → s.val[at_.val + k]? = lit.val[k]?) ↔
            s.val[at_.val + i'.val]? = lit.val[i'.val]? ∧
              ∀ k, i'.val + 1 ≤ k → k < lit.length → s.val[at_.val + k]? = lit.val[k]? := by
          constructor
          · intro agree
            exact ⟨agree i'.val (le_refl _) below, fun k later in_lit => agree k (by omega) in_lit⟩
          · rintro ⟨here, rest⟩ k from_i in_lit
            rcases Nat.eq_or_lt_of_le from_i with same_place | after
            · rw [← same_place]; exact here
            · exact rest k after in_lit
        refine ⟨fun _ => room' still, ?_, by scalar_tac⟩
        rw [← same_answer, is_i3, next, at_s, at_lit]
        simp [still]
      · -- no place of the word is left: the loop ends with the flag
        have below' : ¬ i' < Slice.len lit := by scalar_tac
        simp only [below', ite_false]
        refine (WP.spec_ok _).mpr ?_
        rw [← same_answer]
        have nothing_left : ∀ k, i'.val ≤ k → k < lit.length → s.val[at_.val + k]? = lit.val[k]? := by
          intro k from_i in_lit; omega
        exact ⟨fun _ => ⟨still, nothing_left⟩, fun _ => rfl⟩
    · -- the flag is false: the loop ends with it
      simp only [still]
      refine (WP.spec_ok _).mpr ?_
      rw [← same_answer]
      simp [still]
  · -- the start: the flag and the place the loop is called with
    exact ⟨room, Iff.rfl⟩


/-- A list begins a list after a skip exactly when it fits there and agrees place by place. -/
theorem prefix_of_drop_iff (s lit : List Std.U8) (a : Nat) :
    (a + lit.length ≤ s.length ∧ ∀ k, 0 ≤ k → k < lit.length → s[a + k]? = lit[k]?) ↔
      a + lit.length ≤ s.length ∧ lit <+: s.drop a := by
  constructor
  · rintro ⟨room, agree⟩
    refine ⟨room, ?_⟩
    rw [List.prefix_iff_eq_take]
    apply List.ext_getElem?
    intro k
    by_cases below : k < lit.length
    · rw [List.getElem?_take_of_lt below, List.getElem?_drop, ← agree k (Nat.zero_le k) below,
        Nat.add_comm]
    · rw [List.getElem?_eq_none (show lit.length ≤ k by omega),
        List.getElem?_eq_none (by rw [List.length_take]; omega)]
  · rintro ⟨room, begins⟩
    refine ⟨room, fun k _ below => ?_⟩
    obtain ⟨rest, is_rest⟩ := begins
    have := congrArg (fun l => l[k]?) is_rest
    simp only [List.getElem?_append_left below, List.getElem?_drop] at this
    rw [this]

/-- **`has_at` answers true exactly when the word is the beginning of what is left after the place
`at_`** (and the place is inside the slice); it always returns. -/
theorem has_at_answers (s lit : Slice Std.U8) (at_ : Std.Usize) :
    has_at s at_ lit ⦃ r =>
      r = true ↔ at_.val + lit.length ≤ s.length ∧ lit.val <+: s.val.drop at_.val ⦄ := by
  unfold has_at
  by_cases within : at_ ≤ Slice.len s
  · -- the place is inside the slice: the word fits when what is left is as long as the word
    simp only [within, ite_true]
    step as ⟨ i2, is_i2 ⟩
    have fits : decide (i2 ≥ Slice.len lit) = decide (at_.val + lit.length ≤ s.length) := by
      apply Bool.eq_iff_iff.mpr
      simp only [decide_eq_true_eq, ge_iff_le]
      scalar_tac
    simp only [fits]
    refine WP.spec_mono (has_at_loop_answers s lit at_ _ 0#usize ?_) ?_
    · intro room; exact of_decide_eq_true room
    · intro r answer
      rw [answer, ← prefix_of_drop_iff]
      simp
  · -- the place is past the end: the flag starts false and the loop ends at once
    have outside : ¬ at_.val ≤ s.length := by scalar_tac
    simp only [within, ite_false]
    simp only [Std.bind_ok]
    refine WP.spec_mono (has_at_loop_answers s lit at_ false 0#usize (by simp)) ?_
    intro r answer
    rw [answer]
    simp only [Bool.false_eq_true, false_and, false_iff, not_and]
    omega

/-- **The loop of `has_nul`** from the place `i`, with the flag `found`: it answers true exactly when
the flag is true or a zero byte is at a place from `i` on. -/
theorem has_nul_loop_answers (bytes : Slice Std.U8) (found : Bool) (i : Std.Usize) :
    has_nul_loop bytes found i ⦃ r =>
      r = true ↔ found = true ∨ ∃ k, i.val ≤ k ∧ bytes.val[k]? = some 0#u8 ⦄ := by
  unfold has_nul_loop
  -- the loop ends because the places left are fewer at each round
  apply loop.spec_decr_nat (fun (q : Bool × Std.Usize) => bytes.length - q.2.val)
    (fun (q : Bool × Std.Usize) =>
      (q.1 = true ∨ ∃ k, q.2.val ≤ k ∧ bytes.val[k]? = some 0#u8) ↔
        (found = true ∨ ∃ k, i.val ≤ k ∧ bytes.val[k]? = some 0#u8))
  · rintro ⟨found', i'⟩ same_answer
    simp only at same_answer ⊢
    unfold has_nul_loop.body
    by_cases below : i'.val < bytes.length
    · -- a place is left
      have below' : i' < Slice.len bytes := by scalar_tac
      simp only [below', ite_true]
      by_cases still : found' = true
      · simp only [still, ite_true]
        refine (WP.spec_ok _).mpr ?_
        rw [← same_answer]
        simp [still]
      · -- the flag is false: the byte is read, and the flag is whether it is 0
        simp only [still, Bool.false_eq_true, ite_false]
        step as ⟨ x, is_x ⟩
        step as ⟨ i3, is_i3 ⟩
        have at_i : bytes.val[i'.val]? = some x := by rw [is_x]; simp [below]
        refine ⟨?_, by scalar_tac⟩
        rw [← same_answer, is_i3]
        simp only [still, Bool.false_eq_true, false_or, decide_eq_true_eq]
        constructor
        · rintro (zero | ⟨k, from_i, at_k⟩)
          · exact ⟨i'.val, le_refl _, by rw [at_i, zero]⟩
          · exact ⟨k, by omega, at_k⟩
        · rintro ⟨k, from_i, at_k⟩
          rcases Nat.eq_or_lt_of_le from_i with same_place | after
          · left; rw [← same_place, at_i] at at_k; simpa using at_k
          · right; exact ⟨k, by omega, at_k⟩
    · -- no place is left: the loop ends with the flag
      have below' : ¬ i' < Slice.len bytes := by scalar_tac
      simp only [below', ite_false]
      refine (WP.spec_ok _).mpr ?_
      rw [← same_answer]
      constructor
      · intro still; exact Or.inl still
      · rintro (still | ⟨k, from_i, at_k⟩)
        · exact still
        · have := (List.getElem?_eq_some_iff.mp at_k).1
          have e : bytes.length = bytes.val.length := rfl
          omega
  · exact Iff.rfl

/-- **`has_nul` answers true exactly when the slice has a zero byte**; it always returns. -/
@[step]
theorem has_nul_answers (bytes : Slice Std.U8) :
    has_nul bytes ⦃ r => r = true ↔ 0#u8 ∈ bytes.val ⦄ := by
  unfold has_nul
  refine WP.spec_mono (has_nul_loop_answers bytes false 0#usize) ?_
  intro r answer
  rw [answer]
  simp [List.mem_iff_getElem?]

/-- The constants of the crate (`TRUSTED`, `USER`, ..., `LABEL`) are the bytes of the words they
are named for, as `Text` writes them. -/
theorem the_words_are_the_text :
    TRUSTED.val = Text "trusted." ∧ USER.val = Text "user." ∧ SECURITY.val = Text "security." ∧
    SYSTEM.val = Text "system." ∧ OVERLAY.val = Text "overlay." ∧
    LABEL.val = Text "security.selinux" := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩ <;> first | (unfold TRUSTED; rfl) | (unfold USER; rfl) | (unfold SECURITY; rfl) | (unfold SYSTEM; rfl) | (unfold OVERLAY; rfl) | (unfold LABEL; rfl)

/-- `has_at` with the place 0: the first slice begins with the second. -/
@[step]
theorem has_at_start (s lit : Slice Std.U8) :
    has_at s 0#usize lit ⦃ r => r = true ↔ lit.val <+: s.val ⦄ := by
  refine WP.spec_mono (has_at_answers s lit 0#usize) ?_
  intro r answer
  rw [answer]
  constructor
  · rintro ⟨_, begins⟩; simpa using begins
  · intro begins
    have := begins.length_le
    refine ⟨by simp [Slice.length]; simpa [Slice.length] using this, by simpa using begins⟩

/-- **`namespace` answers the length of the namespace the name begins with**, or 0 when it begins
with none of the four; it always returns. -/
theorem namespace_answers (bytes : Slice Std.U8) :
    «namespace» bytes ⦃ n =>
      (n.val = 0 ∧ ∀ p ∈ Namespaces, ¬ p <+: bytes.val) ∨
      ∃ p ∈ Namespaces, p <+: bytes.val ∧ n.val = p.length ⦄ := by
  obtain ⟨is_trusted, is_user, is_security, is_system, _, _⟩ := the_words_are_the_text
  unfold «namespace»
  -- the four words are tried in this order; the first the name begins with gives its length
  step as ⟨ b1, is_b1 ⟩
  by_cases t : b1 = true
  · simp only [t, ite_true]
    refine (WP.spec_ok _).mpr (Or.inr ⟨Text "trusted.", by simp [Namespaces], ?_, ?_⟩)
    · rw [← is_trusted]; exact is_b1.mp t
    · rw [← is_trusted]; simp [Slice.len]
  simp only [t, Bool.false_eq_true, ite_false]
  step as ⟨ b2, is_b2 ⟩
  by_cases u : b2 = true
  · simp only [u, ite_true]
    refine (WP.spec_ok _).mpr (Or.inr ⟨Text "user.", by simp [Namespaces], ?_, ?_⟩)
    · rw [← is_user]; exact is_b2.mp u
    · rw [← is_user]; simp [Slice.len]
  simp only [u, Bool.false_eq_true, ite_false]
  step as ⟨ b3, is_b3 ⟩
  by_cases s : b3 = true
  · simp only [s, ite_true]
    refine (WP.spec_ok _).mpr (Or.inr ⟨Text "security.", by simp [Namespaces], ?_, ?_⟩)
    · rw [← is_security]; exact is_b3.mp s
    · rw [← is_security]; simp [Slice.len]
  simp only [s, Bool.false_eq_true, ite_false]
  step as ⟨ b4, is_b4 ⟩
  by_cases y : b4 = true
  · simp only [y, ite_true]
    refine (WP.spec_ok _).mpr (Or.inr ⟨Text "system.", by simp [Namespaces], ?_, ?_⟩)
    · rw [← is_system]; exact is_b4.mp y
    · rw [← is_system]; simp [Slice.len]
  simp only [y, Bool.false_eq_true, ite_false]
  -- none of the four: the answer is 0, and none of them is the beginning of the name
  refine (WP.spec_ok _).mpr (Or.inl ⟨rfl, ?_⟩)
  intro p member begins
  simp only [Namespaces, List.mem_cons, List.not_mem_nil, or_false] at member
  rcases member with rfl | rfl | rfl | rfl
  · exact t (is_b1.mpr (by rw [is_trusted]; exact begins))
  · exact u (is_b2.mpr (by rw [is_user]; exact begins))
  · exact s (is_b3.mpr (by rw [is_security]; exact begins))
  · exact y (is_b4.mpr (by rw [is_system]; exact begins))

end OverlayCore
