-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what the scans of `normalize` answer.  `find s from to b` is the place of
-- the first `b` of `s` from the place `from` before the place `to`, or `to`; `find_scheme s` is
-- the place of the first `://` (`SchemeSplit`); the loops that cut the `/` at the end of a key
-- answer the place where `TrimSlashes` of the key from some place stops; the loop that finds the end of
-- the authority answers the length of `Authority`; `push_lower` appends the lower case of a slice.
-- Why it is needed: `normalize` is these scans one after the other.
-- Read before this file: Spec.lean, Bytes.lean.
-- Notation: `loop.spec_decr_nat` proves that a loop returns because a number goes down at each turn
-- while a fact (the invariant) is kept by each turn; `step as ⟨ x, hx ⟩` runs one line of a Rust
-- function and names its result `x` and what is known of it `hx`; `l.take n` and `l.drop n` are the
-- first `n` elements of `l` and `l` without them.
import AuthCore.Spec
import AuthCore.Bytes

open Aeneas Aeneas.Std Result velarx_auth_core

namespace AuthCore

/-- The loop of **`find`**: from the place `i`, it ends with the first place of `s` before `to`, at or
after `i`, that holds `b`, or `to` (`F` is what that place is, written as the length of the bytes
that are not `b` from `i`). -/
theorem find_loop_finds (s : Slice Std.U8) («to» : Std.Usize) (b : Std.U8) (i : Std.Usize)
    (F : Nat) (inside : «to».val ≤ s.length)
    (is_F : i.val + (((s.val.take «to».val).drop i.val).takeWhile
      (fun x => decide (x ≠ b))).length = F) :
    find_loop s «to» b i ⦃ r => r.val = F ⦄ := by
  unfold find_loop
  apply loop.spec_decr_nat (fun (q : Std.Usize) => «to».val - q.val)
    (fun (q : Std.Usize) => q.val + (((s.val.take «to».val).drop q.val).takeWhile
      (fun x => decide (x ≠ b))).length = F)
  · intro i is_F
    unfold find_loop.body
    by_cases below : i.val < «to».val
    · have below' : i < «to» := by scalar_tac
      simp only [below', ite_true]
      step as ⟨ x, is_x ⟩
      have s_len : s.val.length = s.length := rfl
      have in_take : i.val < (s.val.take «to».val).length := by
        simp only [List.length_take]; omega
      have drop_eq : (s.val.take «to».val).drop i.val =
          (s.val.take «to».val)[i.val] :: (s.val.take «to».val).drop (i.val + 1) :=
        List.drop_eq_getElem_cons in_take
      have x_is : x = (s.val.take «to».val)[i.val] := by
        rw [is_x]; simp
      by_cases same : x = b
      · have : ¬ (x != b) = true := by simp [same]
        simp only [bne_iff_ne, ne_eq, same, not_true_eq_false, ite_false]
        refine (WP.spec_ok _).mpr ?_
        rw [drop_eq, ← x_is, List.takeWhile_cons_of_neg (by simp [same])] at is_F
        simpa using is_F
      · have : (x != b) = true := by simpa using same
        simp only [bne_iff_ne, ne_eq, same, not_false_eq_true, ite_true]
        step as ⟨ next, is_next ⟩
        refine ⟨?_, by scalar_tac⟩
        rw [is_next]
        rw [drop_eq, ← x_is] at is_F
        rw [List.takeWhile_cons_of_pos (by simpa using same)] at is_F
        simp only [List.length_cons, ne_eq] at is_F ⊢
        omega
    · have below' : ¬ i < «to» := by scalar_tac
      simp only [below', ite_false]
      refine (WP.spec_ok _).mpr ?_
      have : (s.val.take «to».val).drop i.val = [] := by
        apply List.drop_of_length_le
        simp only [List.length_take]; omega
      rw [this] at is_F
      simpa using is_F
  · exact is_F

/-- **`find`**: the place of the first `b` of `s` from `from` before `to`, or `to`; `from` may be
past `to`, and then it is `from`. -/
@[step] theorem find_finds (s : Slice Std.U8) («from» «to» : Std.Usize) (b : Std.U8)
    (inside : «to».val ≤ s.length) :
    find s «from» «to» b ⦃ r => r.val = «from».val + (((s.val.take «to».val).drop «from».val).takeWhile
      (fun x => decide (x ≠ b))).length ⦄ := by
  unfold find
  exact find_loop_finds s «to» b «from» _ inside rfl

/-- The bytes `://` of the code are `SchemeEnd`. -/
theorem scheme_end_literal : (Array.to_slice (Array.make 3#usize [58#u8, 47#u8, 47#u8])).val = SchemeEnd := by
  simp [Array.to_slice, Array.make, SchemeEnd, Colon, Slash]

/-- The loop of **`find_scheme`**: from the place `i`, with the place found so far (`T` is where the
first `://` of `s` is), it ends with `T`. -/
theorem find_scheme_loop_finds (s : Slice Std.U8) («at» : Option Std.Usize) (i : Std.Usize)
    (T : Option Nat) (_is_T : T = (SchemeSplit s.val).map (·.1.length)) (inside : i.val ≤ s.length)
    (at_says : ∀ a, «at» = some a → T = some a.val)
    (none_says : «at» = none → T = (SchemeSplit (s.val.drop i.val)).map (fun p => p.1.length + i.val)) :
    find_scheme_loop s «at» i ⦃ r => r.map (·.val) = T ⦄ := by
  unfold find_scheme_loop
  apply loop.spec_decr_nat (fun (q : Option Std.Usize × Std.Usize) => s.length - q.2.val)
    (fun (q : Option Std.Usize × Std.Usize) => q.2.val ≤ s.length ∧
      (∀ a, q.1 = some a → T = some a.val) ∧
      (q.1 = none → T = (SchemeSplit (s.val.drop q.2.val)).map (fun p => p.1.length + q.2.val)))
  · rintro ⟨«at», i⟩ ⟨inside, at_says, none_says⟩
    simp only at inside at_says none_says ⊢
    unfold find_scheme_loop.body
    have s_len : s.val.length = s.length := rfl
    have done_at : ∀ (a : Option Std.Usize), (∀ a', a = some a' → T = some a'.val) →
        (a = none → T = none) → a.map (·.val) = T := by
      intro a h1 h2
      cases a with
      | none => simp [h2 rfl]
      | some a' => simp [h1 a' rfl]
    by_cases is_none : «at» = none
    · subst is_none
      simp only [core.option.Option.is_none, Option.isNone_none, ite_true]
      by_cases below : i.val < s.length
      · have below' : i < Slice.len s := by scalar_tac
        simp only [below', ite_true]
        have lit := scheme_end_literal
        simp only [lift, Std.bind_ok]
        step as ⟨ b1, is_b1 ⟩
        have in_s : i.val < s.val.length := below
        have drop_eq : s.val.drop i.val = s.val[i.val] :: s.val.drop (i.val + 1) :=
          List.drop_eq_getElem_cons in_s
        have T_here := none_says rfl
        rw [drop_eq] at T_here
        by_cases found : b1 = true
        · simp only [found, ite_true, Std.bind_ok]
          step as ⟨ next, is_next ⟩
          refine ⟨by scalar_tac, ?_, by simp, by scalar_tac⟩
          · intro a ha
            have a_i : a = i := by simpa using ha.symm
            rw [a_i]
            have begins : SchemeEnd <+: s.val[i.val] :: s.val.drop (i.val + 1) := by
              have := (is_b1.mp found).2
              rw [lit, drop_eq] at this
              exact this
            rw [T_here]
            simp only [SchemeSplit, begins, ↓reduceIte, Option.map_some]
            simp
        · simp only [found, Bool.false_eq_true, ite_false, Std.bind_ok]
          step as ⟨ next, is_next ⟩
          have not_begins : ¬ SchemeEnd <+: s.val[i.val] :: s.val.drop (i.val + 1) := by
            intro begins
            apply found
            apply is_b1.mpr
            refine ⟨by omega, ?_⟩
            rw [lit, drop_eq]
            exact begins
          refine ⟨by scalar_tac, by simp, ?_, by scalar_tac⟩
          intro _
          rw [is_next, T_here]
          simp only [SchemeSplit, not_begins, ↓reduceIte, Option.map_map]
          congr 1
          funext p
          simp
          omega
      · have below' : ¬ i < Slice.len s := by scalar_tac
        simp only [below', ite_false]
        refine (WP.spec_ok _).mpr ?_
        apply done_at none (by simp)
        intro _
        have := none_says rfl
        rw [this, List.drop_of_length_le (by omega)]
        simp [SchemeSplit]
    · cases «at» with
      | none => exact absurd rfl is_none
      | some a =>
        simp only [core.option.Option.is_none, Option.isNone_some, Bool.false_eq_true, ite_false]
        refine (WP.spec_ok _).mpr ?_
        exact done_at _ at_says (by simp)
  · exact ⟨inside, at_says, none_says⟩

/-- **`find_scheme`**: the place of the first `://` of `s`, as `SchemeSplit` cuts it, or none. -/
@[step] theorem find_scheme_finds (s : Slice Std.U8) :
    find_scheme s ⦃ r => r.map (·.val) = (SchemeSplit s.val).map (·.1.length) ⦄ := by
  unfold find_scheme
  exact find_scheme_loop_finds s none 0#usize _ rfl (by simp) (by simp)
    (fun _ => by simp [])

/-- A `/` at the end of a list does not change what is left when the `/` at the end go. -/
theorem trim_after_a_slash (l : Bytes) : TrimSlashes (l ++ [Slash]) = TrimSlashes l := by
  unfold TrimSlashes
  rw [List.reverse_append]
  simp

/-- A list that ends with a byte other than `/` is left as it is. -/
theorem trim_after_another_byte (l : Bytes) (c : Std.U8) (not_slash : c ≠ Slash) :
    TrimSlashes (l ++ [c]) = l ++ [c] := by
  unfold TrimSlashes
  rw [List.reverse_append]
  simp [not_slash]

/-- The loop of the cut of the `/` at the end of the key from the place `after` (the loop 0 of
`normalize`): from the place `end`, it ends at `after` and the length of what is left. -/
theorem trim_loop_cuts (key : Slice Std.U8) (after «end» : Std.Usize) (F : Nat)
    (inside : «end».val ≤ key.length) (after_le : after.val ≤ «end».val)
    (is_F : after.val + (TrimSlashes ((key.val.drop after.val).take («end».val - after.val))).length = F) :
    normalize_loop0 key after «end» ⦃ r => r.val = F ⦄ := by
  unfold normalize_loop0
  apply loop.spec_decr_nat (fun (q : Std.Usize) => q.val)
    (fun (q : Std.Usize) => q.val ≤ key.length ∧ after.val ≤ q.val ∧
      after.val + (TrimSlashes ((key.val.drop after.val).take (q.val - after.val))).length = F)
  · intro e ⟨inside, after_le, is_F⟩
    unfold normalize_loop0.body
    have key_len : key.val.length = key.length := rfl
    by_cases above : e.val > after.val
    · have above' : e > after := by scalar_tac
      simp only [above', ite_true]
      step as ⟨ i, is_i ⟩
      step as ⟨ c, is_c ⟩
      have in_drop : e.val - after.val - 1 < (key.val.drop after.val).length := by
        simp only [List.length_drop]; omega
      have c_is : c = (key.val.drop after.val)[e.val - after.val - 1] := by
        rw [is_c]; simp [List.getElem_drop]
        congr 1; omega
      have grows : (key.val.drop after.val).take (e.val - after.val) =
          (key.val.drop after.val).take (e.val - after.val - 1) ++ [c] := by
        have := take_one_more (key.val.drop after.val) (e.val - after.val - 1) in_drop
        rw [← c_is] at this
        rw [← this]
        congr 1
        omega
      by_cases slash : c = 47#u8
      · simp only [slash, ite_true]
        refine (WP.spec_ok _).mpr ?_
        refine ⟨by scalar_tac, by scalar_tac, ?_, by scalar_tac⟩
        rw [grows, show c = Slash from slash, trim_after_a_slash] at is_F
        have : i.val - after.val = e.val - after.val - 1 := by omega
        rw [this]
        exact is_F
      · simp only [slash, ite_false]
        refine (WP.spec_ok _).mpr ?_
        rw [grows, trim_after_another_byte _ _ (by simpa [Slash] using slash)] at is_F
        simp only [List.length_append, List.length_take, List.length_drop, List.length_singleton] at is_F
        show e.val = F
        omega
    · have above' : ¬ e > after := by scalar_tac
      simp only [above', ite_false]
      refine (WP.spec_ok _).mpr ?_
      have : e.val = after.val := by omega
      rw [this] at is_F
      simp [TrimSlashes] at is_F
      omega
  · exact ⟨inside, after_le, is_F⟩

/-- What `Authority` of a list that begins with `c` is. -/
theorem authority_cons (c : Std.U8) (l : Bytes) : Authority (c :: l) =
    if c = Slash ∨ c = Question ∨ c = Hash then [] else c :: Authority l := by
  unfold Authority
  by_cases d : c = Slash ∨ c = Question ∨ c = Hash
  · simp only [d, ↓reduceIte]
    rw [List.takeWhile_cons_of_neg]
    rcases d with d | d | d <;> simp [d]
  · simp only [d, ↓reduceIte]
    rw [List.takeWhile_cons_of_pos]
    simpa using d

/-- The loop 1 of `normalize`: from the place `stop`, it ends with the place where `Authority` of
what is left of the key before `to` (the end once the `/` at the end are cut) stops (`F`). -/
theorem authority_loop_ends (key : Slice Std.U8) («to» stop : Std.Usize) (F : Nat)
    (inside : stop.val ≤ «to».val) (to_le : «to».val ≤ key.length)
    (is_F : stop.val + (Authority ((key.val.take «to».val).drop stop.val)).length = F) :
    normalize_loop1 key «to» stop ⦃ r => r.val = F ⦄ := by
  unfold normalize_loop1
  apply loop.spec_decr_nat (fun (q : Std.Usize) => «to».val - q.val)
    (fun (q : Std.Usize) => q.val ≤ «to».val ∧
      q.val + (Authority ((key.val.take «to».val).drop q.val)).length = F)
  · intro e ⟨inside, is_F⟩
    unfold normalize_loop1.body
    have key_len : key.val.length = key.length := rfl
    by_cases below : e.val < «to».val
    · have below' : e < «to» := by scalar_tac
      simp only [below', ite_true]
      step as ⟨ c, is_c ⟩
      have drop_eq : (key.val.take «to».val).drop e.val =
          c :: (key.val.take «to».val).drop (e.val + 1) := by
        rw [List.drop_eq_getElem_cons (by simp; omega)]
        simp [is_c]
      have stops_here : (c = Slash ∨ c = Question ∨ c = Hash) → e.val = F := by
        intro d
        rw [drop_eq, authority_cons] at is_F
        simp only [d, ↓reduceIte] at is_F
        simpa using is_F
      split
      · simp only [Std.bind_ok, ↓reduceIte]
        refine (WP.spec_ok _).mpr ?_
        exact stops_here (Or.inl rfl)
      · simp only [Std.bind_ok, ↓reduceIte]
        refine (WP.spec_ok _).mpr ?_
        exact stops_here (Or.inr (Or.inl rfl))
      · simp only [Std.bind_ok, ↓reduceIte]
        refine (WP.spec_ok _).mpr ?_
        exact stops_here (Or.inr (Or.inr rfl))
      · rename_i h1 h2 h3
        simp only [Std.bind_ok, Bool.false_eq_true, ↓reduceIte]
        step as ⟨ next, is_next ⟩
        have not_delim : ¬ (c = Slash ∨ c = Question ∨ c = Hash) := by
          rintro (d | d | d)
          · exact h1 (by rw [d]; rfl)
          · exact h2 (by rw [d]; rfl)
          · exact h3 (by rw [d]; rfl)
        rw [drop_eq, authority_cons] at is_F
        simp only [not_delim, ↓reduceIte] at is_F
        simp only [List.length_cons] at is_F
        refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        rw [is_next]
        omega
    · have below' : ¬ e < «to» := by scalar_tac
      simp only [below', ite_false]
      refine (WP.spec_ok _).mpr ?_
      have : e.val = «to».val := by omega
      have : (key.val.take «to».val).drop e.val = [] := List.drop_of_length_le (by simp; omega)
      rw [this] at is_F
      simp [Authority] at is_F
      omega
  · exact ⟨inside, is_F⟩

/-- **`extend_from_slice`** of bytes appends them, when the vector it makes fits in a `usize`. -/
theorem extend_appends (v : alloc.vec.Vec Std.U8) (s : Slice Std.U8)
    (room : v.length + s.length ≤ Std.Usize.max) :
    alloc.vec.Vec.extend_from_slice core.clone.CloneU8 v s ⦃ r => r.val = v.val ++ s.val ⦄ := by
  unfold alloc.vec.Vec.extend_from_slice
  simp only [room, ↓reduceDIte]
  step as ⟨ s', is_s', _ ⟩
  rw [alloc.vec.Vec.from_val, is_s']

/-- **`push_lower`**'s loop: from the place `i`, it appends the lower case of the bytes of `s` from
`i` on, when the vector made fits in a `usize`. -/
theorem push_lower_loop_appends (s : Slice Std.U8) (out : alloc.vec.Vec Std.U8) (i : Std.Usize)
    (inside : i.val ≤ s.length)
    (room : out.length + (s.length - i.val) ≤ Std.Usize.max) :
    push_lower_loop out s i ⦃ r => r.val = out.val ++ (s.val.drop i.val).map LowerByte ⦄ := by
  unfold push_lower_loop
  apply loop.spec_decr_nat (fun (q : alloc.vec.Vec Std.U8 × Std.Usize) => s.length - q.2.val)
    (fun (q : alloc.vec.Vec Std.U8 × Std.Usize) => q.2.val ≤ s.length ∧
      q.1.val ++ (s.val.drop q.2.val).map LowerByte = out.val ++ (s.val.drop i.val).map LowerByte ∧
      out.length + (s.length - i.val) ≤ Std.Usize.max)
  · rintro ⟨copied, i'⟩ ⟨inside, same_total, total_fits⟩
    simp only at inside same_total total_fits ⊢
    unfold push_lower_loop.body
    by_cases below : i'.val < s.length
    · have below' : i' < Slice.len s := by scalar_tac
      simp only [below', ite_true]
      have lengths := congrArg List.length same_total
      simp only [List.length_append, List.length_map, List.length_drop] at lengths
      have room' : copied.val.length < Std.Usize.max := by
        have : copied.length = copied.val.length := rfl
        have : out.length = out.val.length := rfl
        have : s.val.length = s.length := rfl
        omega
      step as ⟨ x, is_x ⟩
      step as ⟨ y, is_y ⟩
      step as ⟨ copied1, is_copied1 ⟩
      step as ⟨ next, is_next ⟩
      refine ⟨by scalar_tac, ?_, total_fits, by scalar_tac⟩
      rw [is_copied1, is_next, ← same_total, is_y, is_x]
      rw [List.drop_eq_getElem_cons (show i'.val < s.val.length from below)]
      simp only [List.map_cons, List.append_assoc, List.singleton_append]
    · have below' : ¬ i' < Slice.len s := by scalar_tac
      simp only [below', ite_false]
      refine (WP.spec_ok _).mpr ?_
      rw [List.drop_of_length_le (by have : s.val.length = s.length := rfl; omega)] at same_total
      simpa using same_total
  · exact ⟨inside, rfl, room⟩

/-- **`push_lower`** appends the lower case of the bytes of `s` to `out`, when the vector made fits
in a `usize`. -/
theorem push_lower_appends (out : alloc.vec.Vec Std.U8) (s : Slice Std.U8)
    (room : out.length + s.length ≤ Std.Usize.max) :
    push_lower out s ⦃ r => r.val = out.val ++ s.val.map LowerByte ⦄ := by
  unfold push_lower
  have := push_lower_loop_appends s out 0#usize (by simp) (by simpa using room)
  simpa using this

end AuthCore
