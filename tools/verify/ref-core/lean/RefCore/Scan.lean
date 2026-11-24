-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `find`, `find_last` and `is_lit` do: the first place of a byte in a
-- piece, the last one, and whether a piece is a given literal. It also shows where `find` and
-- `find_last` go when the byte is where a list says it is.
-- Why it is needed: `parse` cuts the string with them (at the `@`, at the slashes, at the colon),
-- so every claim about the parts goes through these three.
-- Read before this file: Pieces.lean, ByteClasses.lean.
-- Notation: `loop.spec_decr_nat` proves that a loop returns because a number goes down at each
-- turn while a fact (the invariant) is kept by each turn; `step as ⟨ x, hx ⟩` runs one line of a
-- Rust function and names its result `x` and what is known of it `hx`.
import RefCore.Pieces
import RefCore.ByteClasses
open Aeneas Aeneas.Std Result velarx_ref_core
namespace RefCore

/-- `find` goes to the first `b` of the piece, or to its end: before that place there is no `b`, and
at it there is one. -/
@[step] theorem find_looks_for_the_byte (s : Slice Std.U8) (start stop : Std.Usize) (b : Std.U8)
    (ordered : start.val ≤ stop.val) (inside : stop.val ≤ s.length) :
    find s start stop b ⦃ r =>
      start.val ≤ r.val ∧ r.val ≤ stop.val ∧
      (∀ x ∈ Piece (Bytes s.val) start r, x ≠ b.val) ∧
      (r.val < stop.val → (Bytes s.val)[r.val]? = some b.val) ⦄ := by
  unfold find find_loop
  apply loop.spec_decr_nat (fun (i : Std.Usize) => stop.val - i.val)
    (fun (i : Std.Usize) => start.val ≤ i.val ∧ i.val ≤ stop.val ∧ ∀ x ∈ Piece
        (Bytes s.val) start i, x ≠ b.val)
  · intro i ⟨after_start, before_stop, none_so_far⟩
    unfold find_loop.body
    split
    · rename_i below
      step as ⟨ x, x_post ⟩
      split
      · rename_i different
        step as ⟨ next, next_post ⟩
        have x_at := bytes_at s i x (by scalar_tac) x_post
        have not_it := (bne_says x b).mp different
        refine ⟨by scalar_tac, by scalar_tac, ?_, by scalar_tac⟩
        rw [next_post, piece_snoc _ _ _ _ after_start x_at]
        intro y y_in
        rcases List.mem_append.mp y_in with before | here
        · exact none_so_far y before
        · rw [List.mem_singleton.mp here]
          exact not_it
      · rename_i same
        have x_at := bytes_at s i x (by scalar_tac) x_post
        have is_it : x.val = b.val := by simpa [bne_says, eq_says] using same
        simp only [WP.spec_ok]
        exact ⟨after_start, before_stop, none_so_far, fun _ => by rw [← is_it]; exact x_at⟩
    · rename_i not_below
      simp only [WP.spec_ok]
      exact ⟨after_start, before_stop, none_so_far, fun below => by scalar_tac⟩
  · exact ⟨by scalar_tac, ordered, by simp [piece_empty]⟩

/-- When the byte is at a place of the piece and nowhere before it, `find` goes to that place. -/
theorem find_goes_to_the_first (s : Slice Std.U8) (start stop : Std.Usize) (b : Std.U8)
    (ordered : start.val ≤ stop.val) (inside : stop.val ≤ s.length) (place : Nat)
    (after : start.val ≤ place) (before : place < stop.val)
    (there : (Bytes s.val)[place]? = some b.val)
    (none_before : ∀ x ∈ Piece (Bytes s.val) start place, x ≠ b.val) :
    find s start stop b ⦃ r => r.val = place ⦄ := by
  step as ⟨ r, r_after, r_before, r_none, r_found ⟩
  by_cases same : r.val = place
  · exact same
  · exfalso
    rcases Nat.lt_or_gt_of_ne same with earlier | later
    · exact none_before b.val (by
        have := r_found (by omega)
        exact piece_contains _ _ _ r.val _ r_after earlier this) rfl
    · exact r_none b.val (piece_contains _ _ _ place _ after later there) rfl

/-- When the byte is nowhere in the piece, `find` goes to its end. -/
theorem find_goes_to_the_end (s : Slice Std.U8) (start stop : Std.Usize) (b : Std.U8)
    (ordered : start.val ≤ stop.val) (inside : stop.val ≤ s.length)
    (none_in : ∀ x ∈ Piece (Bytes s.val) start stop, x ≠ b.val) :
    find s start stop b ⦃ r => r.val = stop.val ⦄ := by
  step as ⟨ r, r_after, r_before, r_none, r_found ⟩
  by_contra not_end
  have below : r.val < stop.val := by omega
  exact none_in b.val (piece_contains _ _ _ r.val _ r_after below (r_found below)) rfl

/-- `find_last` gives the last place of `b` in the piece, if there is one. -/
@[step] theorem find_last_looks_for_the_last_byte (s : Slice Std.U8) (start stop : Std.Usize)
    (b : Std.U8) (ordered : start.val ≤ stop.val) (inside : stop.val ≤ s.length) :
    find_last s start stop b ⦃ r =>
      (r = none → ∀ x ∈ Piece (Bytes s.val) start stop, x ≠ b.val) ∧
      (∀ k, r = some k → start.val ≤ k.val ∧ k.val < stop.val ∧
        (Bytes s.val)[k.val]? = some b.val ∧
        ∀ x ∈ Piece (Bytes s.val) (k.val + 1) stop, x ≠ b.val) ⦄ := by
  unfold find_last find_last_loop
  apply loop.spec_decr_nat (fun (q : Option Std.Usize × Std.Usize) => stop.val - q.2.val)
    (fun (q : Option Std.Usize × Std.Usize) => start.val ≤ q.2.val ∧ q.2.val ≤ stop.val ∧
      (q.1 = none → ∀ x ∈ Piece (Bytes s.val) start q.2, x ≠ b.val) ∧
      (∀ k, q.1 = some k → start.val ≤ k.val ∧ k.val < q.2.val ∧
        (Bytes s.val)[k.val]? = some b.val ∧
        ∀ x ∈ Piece (Bytes s.val) (k.val + 1) q.2, x ≠ b.val))
  · rintro ⟨last, i⟩ ⟨after_start, before_stop, none_so_far, some_so_far⟩
    simp only at after_start before_stop none_so_far some_so_far
    unfold find_last_loop.body
    dsimp only
    split
    · rename_i below
      step as ⟨ x, x_post ⟩
      have x_at := bytes_at s i x (by scalar_tac) x_post
      split
      · rename_i found
        have is_b : x.val = b.val := (eq_says x b).mp found
        simp only [Std.bind_ok]
        step as ⟨ next, next_post ⟩
        refine ⟨by scalar_tac, by scalar_tac, by simp, fun k same => ?_, by scalar_tac⟩
        simp only [Option.some.injEq] at same
        subst same
        refine ⟨after_start, by scalar_tac, ?_, ?_⟩
        · rw [← is_b]; exact x_at
        · rw [next_post, piece_empty]; simp
      · rename_i missed
        have not_b : x.val ≠ b.val := fun same => missed ((eq_says x b).mpr same)
        simp only [Std.bind_ok]
        step as ⟨ next, next_post ⟩
        have snoc := piece_snoc (Bytes s.val) start i x.val after_start x_at
        refine ⟨by scalar_tac, by scalar_tac, fun is_none => ?_, fun k is_k => ?_, by scalar_tac⟩
        · rw [next_post, snoc]
          intro y y_in
          rcases List.mem_append.mp y_in with before | here
          · exact none_so_far is_none y before
          · rw [List.mem_singleton.mp here]; exact not_b
        · obtain ⟨k_after, k_before, k_at, k_none⟩ := some_so_far k is_k
          refine ⟨k_after, by scalar_tac, k_at, ?_⟩
          rw [next_post, piece_snoc (Bytes s.val) (k.val + 1) i x.val (by scalar_tac) x_at]
          intro y y_in
          rcases List.mem_append.mp y_in with before | here
          · exact k_none y before
          · rw [List.mem_singleton.mp here]; exact not_b
    · rename_i not_below
      simp only [WP.spec_ok]
      have at_end : i.val = stop.val := by scalar_tac
      rw [at_end] at none_so_far some_so_far
      exact ⟨none_so_far, fun k is_k => by
        obtain ⟨a, b, c, d⟩ := some_so_far k is_k
        exact ⟨a, b, c, d⟩⟩
  · refine ⟨by scalar_tac, ordered, by simp [piece_empty], fun k found => by simp at found⟩

/-- `is_lit` says `true` exactly when the piece is the bytes of the literal. -/
@[step] theorem is_lit_compares_the_piece (s : Slice Std.U8) (start stop : Std.Usize)
    (lit : Slice Std.U8) (ordered : start.val ≤ stop.val) (inside : stop.val ≤ s.length) :
    is_lit s start stop lit ⦃ r =>
      (r = true ↔ Piece (Bytes s.val) start stop = Bytes lit.val) ⦄ := by
  unfold is_lit
  step as ⟨ width, width_post ⟩
  apply loop.spec_decr_nat (fun (q : Bool × Std.Usize) => if q.1 = true
      then lit.length + 1 - q.2.val else 0)
    (fun (q : Bool × Std.Usize) => q.2.val ≤ lit.length ∧
      (q.1 = true ↔ width.val = lit.length ∧
        Piece (Bytes s.val) start (start.val + q.2.val) = (Bytes lit.val).take q.2.val))
  · rintro ⟨same, i⟩ ⟨i_inside, same_so_far⟩
    simp only at i_inside same_so_far
    unfold is_lit_loop.body
    dsimp only
    split
    · rename_i going
      have going' : same = true := going
      obtain ⟨width_is, so_far⟩ := same_so_far.mp going'
      split
      · rename_i below
        step as ⟨ at_, at_post ⟩
        step as ⟨ x, x_post ⟩
        step as ⟨ y, y_post ⟩
        step as ⟨ next, next_post ⟩
        have below' : i.val < lit.length := by scalar_tac
        have x_at := bytes_at s at_ x (by scalar_tac) x_post
        have y_at := bytes_at lit i y below' y_post
        have place : at_.val = start.val + i.val := by scalar_tac
        have snoc_s := piece_snoc (Bytes s.val) start at_.val x.val (by scalar_tac) x_at
        have snoc_lit : (Bytes lit.val).take (i.val + 1) =
            (Bytes lit.val).take i.val ++ [y.val] := by
          rw [List.take_add_one, y_at]
          rfl
        have next_place : start.val + next.val = at_.val + 1 := by scalar_tac
        refine ⟨by scalar_tac, ?_, ?_⟩
        · rw [next_place, snoc_s, next_post, snoc_lit, place, so_far]
          simp [width_is, UScalar.eq_equiv]
        · by_cases same_byte : decide (x = y) = true
          · simp only [same_byte, ite_true]; scalar_tac
          · simp only [same_byte]; scalar_tac
      · rename_i not_below
        have at_end : i.val = lit.length := by scalar_tac
        have stop_is : stop.val = start.val + lit.length := by scalar_tac
        simp only [WP.spec_ok, going', true_iff]
        rw [stop_is, ← at_end, so_far]
        have : (Bytes lit.val).take lit.length = Bytes lit.val := by
          apply List.take_of_length_le; simp
        rw [at_end, this]
    · rename_i stopped
      have stopped' : same = false := by simpa using stopped
      simp only [WP.spec_ok, stopped', Bool.false_eq_true, false_iff]
      intro equal
      have lengths := piece_length (Bytes s.val) start stop ordered (by simpa using inside)
      rw [equal] at lengths
      have width_is : width.val = lit.length := by simp at lengths; scalar_tac
      have prefix_is := piece_take (Bytes s.val) start stop (start.val + i.val)
        (by scalar_tac) (by scalar_tac)
      rw [equal, show start.val + i.val - start.val = i.val by omega] at prefix_is
      have same_true := same_so_far.mpr ⟨width_is, prefix_is.symm⟩
      simp [stopped'] at same_true
  · have zero : (0#usize).val = 0 := rfl
    simp only [zero, piece_empty, add_zero, List.take_zero, and_true, decide_eq_true_eq]
    refine ⟨by scalar_tac, ?_⟩
    rw [UScalar.eq_equiv]
    scalar_tac

/-- When the text between two places is `X` and then what begins with the byte (or nothing), and
the byte is not in `X`, `find` goes to the end of `X`. -/
theorem find_goes_to_the_end_of_the_cut (s : Slice Std.U8) (start stop : Std.Usize) (b : Std.U8)
    (before after : List Nat) (ordered : start.val ≤ stop.val) (inside : stop.val ≤ s.length)
    (cut : Piece (Bytes s.val) start stop = before ++ after) (none_in : ∀ x ∈ before, x ≠ b.val)
    (what_follows : after = [] ∨ ∃ rest, after = b.val :: rest) :
    find s start stop b ⦃ r => r.val = start.val + before.length ⦄ := by
  have width := piece_length (Bytes s.val) start stop ordered (by simpa using inside)
  rw [cut] at width
  simp only [List.length_append] at width
  rcases what_follows with empty | ⟨rest, after_is⟩
  · rw [empty] at cut width
    simp only [List.append_nil, List.length_nil, Nat.add_zero] at cut width
    refine WP.spec_mono (find_goes_to_the_end s start stop b ordered inside (by rw [cut]; exact
      none_in)) ?_
    intro r is_end
    omega
  · have middle := piece_middle (Bytes s.val) start stop [] before after ordered
      (by simpa using inside) (by rw [cut]; simp)
    simp only [List.length_nil, Nat.add_zero] at middle
    rw [after_is] at width
    simp only [List.length_cons] at width
    have byte_at : (Bytes s.val)[start.val + before.length]? = some b.val := by
      apply piece_byte (Bytes s.val) start stop before.length b.val
      rw [cut, after_is, List.getElem?_append_right (le_refl _)]
      simp
    exact find_goes_to_the_first s start stop b ordered inside (start.val + before.length)
      (by omega) (by omega) byte_at (by rw [middle]; exact none_in)

/-- When the text between two places is something, a byte, and then what has no such byte,
`find_last` finds that byte. -/
theorem find_last_finds_the_last_byte (s : Slice Std.U8) (start stop : Std.Usize) (b : Std.U8)
    (before after : List Nat) (ordered : start.val ≤ stop.val) (inside : stop.val ≤ s.length)
    (cut : Piece (Bytes s.val) start stop = before ++ b.val :: after)
    (none_after : ∀ x ∈ after, x ≠ b.val) :
    find_last s start stop b ⦃ r => ∃ k : Std.Usize, r = some k ∧ k.val = start.val +
      before.length ⦄ := by
  have width := piece_length (Bytes s.val) start stop ordered (by simpa using inside)
  rw [cut] at width
  simp only [List.length_append, List.length_cons] at width
  have byte_at : (Bytes s.val)[start.val + before.length]? = some b.val := by
    apply piece_byte (Bytes s.val) start stop before.length b.val
    rw [cut, List.getElem?_append_right (le_refl _)]
    simp
  have after_piece : Piece (Bytes s.val) (start.val + before.length + 1) stop.val = after := by
    have := piece_middle (Bytes s.val) start stop (before ++ [b.val]) after [] ordered
      (by simpa using inside) (by rw [cut]; simp)
    simp only [List.length_append, List.length_singleton] at this
    rw [← Nat.add_assoc] at this
    rw [show start.val + before.length + 1 + after.length = stop.val by omega] at this
    exact this
  step as ⟨ o, o_none, o_some ⟩
  cases o with
  | none =>
    exfalso
    exact o_none rfl b.val (piece_contains _ _ _ (start.val + before.length) b.val (by omega)
      (by omega) byte_at) rfl
  | some k =>
    obtain ⟨k_after, k_before, k_at, k_none⟩ := o_some k rfl
    refine ⟨k, rfl, ?_⟩
    by_contra not_same
    rcases Nat.lt_or_gt_of_ne not_same with earlier | later
    · exact k_none b.val (piece_contains _ _ _ (start.val + before.length) b.val (by omega)
        (by omega) byte_at) rfl
    · have in_after : b.val ∈ Piece (Bytes s.val) (start.val + before.length + 1) stop :=
        piece_contains _ _ _ k.val b.val (by omega) k_before k_at
      rw [after_piece] at in_after
      exact none_after _ in_after rfl

/-- When there is no such byte in the text between two places, `find_last` finds nothing. -/
theorem find_last_finds_nothing (s : Slice Std.U8) (start stop : Std.Usize) (b : Std.U8)
    (ordered : start.val ≤ stop.val) (inside : stop.val ≤ s.length)
    (none_in : ∀ x ∈ Piece (Bytes s.val) start stop, x ≠ b.val) :
    find_last s start stop b ⦃ r => r = none ⦄ := by
  step as ⟨ o, o_none, o_some ⟩
  cases o with
  | none => rfl
  | some k =>
    obtain ⟨k_after, k_before, k_at, _⟩ := o_some k rfl
    exact absurd rfl (none_in b.val (piece_contains _ _ _ k.val b.val k_after k_before k_at))

end RefCore
