-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what the checks of a host do: the port (`port_bad`), the address in
-- brackets (`bracket_bad`), the domain name (`domain_bad`) and the host (`host_bad`).  Each one,
-- when it finds nothing wrong, has read what Spec.lean defines (`IsPort`, `IsBracketed`,
-- `IsDomainHost`, `IsHost`). It also shows the other direction: the address check, the domain
-- check and the host check find nothing wrong in every address, domain name and host of the
-- grammar (the port check says it both ways).
-- Why it is needed: the host of a reference is put in a URL, so it is the part that must be
-- checked most closely.
-- Read before this file: Spec.lean, Scan.lean, DomainShapes.lean.
-- Notation: a function `f_bad` answers `none` when it finds nothing wrong and `some place` for the
-- place of the first byte that is wrong; `found = none ↔ ...` in a loop says "nothing was wrong
-- before, and every byte so far is good".
import RefCore.Scan
import RefCore.DomainShapes
import RefCore.Safety
open Aeneas Aeneas.Std Result velarx_ref_core
namespace RefCore

/-- `is_none` says `true` exactly for `None`. -/
theorem is_none_says {α : Type} (x : Option α) :
    core.option.Option.is_none x = true ↔ x = none := by
  cases x <;> simp [core.option.Option.is_none]

/-- `is_some` says `true` exactly for what is not `None`. -/
theorem is_some_says {α : Type} (x : Option α) :
    core.option.Option.is_some x = true ↔ x ≠ none := by
  cases x <;> simp [core.option.Option.is_some]

/-- The loop of `port_bad` finds nothing wrong exactly when nothing was wrong before and every byte
from the start to the end is a digit. -/
@[step] theorem port_loop_checks_the_digits (s : Slice Std.U8) (start stop : Std.Usize)
    (bad : Option Std.Usize) (ordered : start.val ≤ stop.val) (inside : stop.val ≤ s.length) :
    port_bad_loop s stop bad start ⦃ r =>
      (r = none ↔ bad = none ∧ ∀ x ∈ Piece (Bytes s.val) start stop, IsDigit x) ⦄ := by
  unfold port_bad_loop
  apply loop.spec_decr_nat (fun (q : Option Std.Usize × Std.Usize) => stop.val - q.2.val)
    (fun (q : Option Std.Usize × Std.Usize) => start.val ≤ q.2.val ∧ q.2.val ≤ stop.val ∧
      (q.1 = none ↔ bad = none ∧ ∀ x ∈ Piece (Bytes s.val) start q.2, IsDigit x))
  · rintro ⟨found, i⟩ ⟨after_start, before_stop, so_far⟩
    simp only at after_start before_stop so_far
    unfold port_bad_loop.body
    dsimp only
    split
    · rename_i below
      split
      · rename_i unfound
        have unfound' := (is_none_says found).mp unfound
        step as ⟨ x, x_post ⟩
        step as ⟨ digit, digit_post ⟩
        have x_at := bytes_at s i x (by scalar_tac) x_post
        have snoc := piece_snoc (Bytes s.val) start i x.val after_start x_at
        split
        · rename_i is_digit
          simp only [Std.bind_ok]
          step as ⟨ next, next_post ⟩
          refine ⟨by scalar_tac, by scalar_tac, ?_, by scalar_tac⟩
          rw [next_post, snoc]
          exact scan_good_byte _ _ _ _ _ so_far unfound' (digit_post.mp is_digit)
        · rename_i not_digit
          simp only [Std.bind_ok]
          step as ⟨ next, next_post ⟩
          refine ⟨by scalar_tac, by scalar_tac, ?_, by scalar_tac⟩
          rw [next_post, snoc]
          exact scan_bad_byte _ _ _ _ _ (fun is_it => not_digit (digit_post.mpr is_it))
      · rename_i found_one
        simp only [WP.spec_ok]
        exact scan_stops _ _ _ _ _ _ _ after_start before_stop so_far
          (fun is_none => found_one ((is_none_says found).mpr is_none))
    · rename_i not_below
      simp only [WP.spec_ok]
      have at_end : i.val = stop.val := by scalar_tac
      rw [at_end] at so_far
      exact so_far
  · exact ⟨by scalar_tac, ordered, by simp [piece_empty]⟩

/-- A piece of a text with something in it is not empty. -/
theorem piece_not_empty (text : List Nat) (start stop : Nat) (after : start < stop)
    (inside : stop ≤ text.length) : Piece text start stop ≠ [] := by
  intro empty
  have := piece_length text start stop (by omega) inside
  rw [empty] at this
  simp at this
  omega

/-- `port_bad` finds nothing wrong exactly in a port: one or more digits. -/
@[step] theorem port_bad_accepts_exactly_ports (s : Slice Std.U8) (start stop : Std.Usize)
    (ordered : start.val ≤ stop.val) (inside : stop.val ≤ s.length) :
    port_bad s start stop ⦃ r => (r = none ↔ IsPort (Piece (Bytes s.val) start stop)) ⦄ := by
  unfold port_bad
  split
  · rename_i empty
    simp only [Std.bind_ok]
    step as ⟨ r, r_post ⟩
    have same : start.val = stop.val := by scalar_tac
    simp only [same, piece_empty, IsPort, ne_eq, not_true_eq_false, false_and, iff_false]
    simp only [reduceCtorEq, false_and] at r_post
    exact fun is_none => r_post.mp is_none
  · rename_i filled
    simp only [Std.bind_ok]
    step as ⟨ r, r_post ⟩
    have below : start.val < stop.val := by scalar_tac
    simp only [IsPort] at r_post ⊢
    rw [r_post]
    exact ⟨fun all => ⟨piece_not_empty _ _ _ below (by simpa using inside), all⟩,
        fun both => both.2⟩

/-- The loop of `bracket_bad` finds nothing wrong exactly when nothing was wrong before and every
byte between the brackets is a hex digit or a colon. -/
@[step] theorem bracket_loop_checks_the_inside (s : Slice Std.U8) (start close : Std.Usize)
    (bad : Option Std.Usize) (ordered : start.val ≤ close.val) (inside : close.val ≤ s.length) :
    bracket_bad_loop s close bad start ⦃ r =>
      (r = none ↔ bad = none ∧ ∀ x ∈ Piece (Bytes s.val) start close, IsHex x ∨ x = 58) ⦄ := by
  unfold bracket_bad_loop
  apply loop.spec_decr_nat (fun (q : Option Std.Usize × Std.Usize) => close.val - q.2.val)
    (fun (q : Option Std.Usize × Std.Usize) => start.val ≤ q.2.val ∧ q.2.val ≤ close.val ∧
      (q.1 = none ↔ bad = none ∧
        ∀ x ∈ Piece (Bytes s.val) start q.2, IsHex x ∨ x = 58))
  · rintro ⟨found, i⟩ ⟨after_start, before_stop, so_far⟩
    simp only at after_start before_stop so_far
    unfold bracket_bad_loop.body
    dsimp only
    split
    · rename_i below
      split
      · rename_i unfound
        have unfound' := (is_none_says found).mp unfound
        step as ⟨ x, x_post ⟩
        step as ⟨ hex, hex_post ⟩
        have x_at := bytes_at s i x (by scalar_tac) x_post
        have snoc := piece_snoc (Bytes s.val) start i x.val after_start x_at
        split
        · rename_i is_hex
          simp only [Std.bind_ok]
          step as ⟨ next, next_post ⟩
          refine ⟨by scalar_tac, by scalar_tac, ?_, by scalar_tac⟩
          rw [next_post, snoc]
          exact scan_good_byte _ _ _ _ _ so_far unfound' (Or.inl (hex_post.mp is_hex))
        · rename_i not_hex
          split
          · rename_i not_colon
            simp only [Std.bind_ok]
            step as ⟨ next, next_post ⟩
            refine ⟨by scalar_tac, by scalar_tac, ?_, by scalar_tac⟩
            rw [next_post, snoc]
            exact scan_bad_byte _ _ _ _ _ (fun is_it => is_it.elim
              (fun is_hex => not_hex (hex_post.mpr is_hex))
              (fun is_colon => (bne_says x 58#u8).mp not_colon (by simpa using is_colon)))
          · rename_i colon
            simp only [Std.bind_ok]
            step as ⟨ next, next_post ⟩
            refine ⟨by scalar_tac, by scalar_tac, ?_, by scalar_tac⟩
            rw [next_post, snoc]
            have is_colon : x.val = 58 := by
              have : ¬ ((x != 58#u8) = true) := colon
              simpa [bne_says] using this
            exact scan_good_byte _ _ _ _ _ so_far unfound' (Or.inr is_colon)
      · rename_i found_one
        simp only [WP.spec_ok]
        exact scan_stops _ _ _ _ _ _ _ after_start before_stop so_far
          (fun is_none => found_one ((is_none_says found).mpr is_none))
    · rename_i not_below
      simp only [WP.spec_ok]
      have at_end : i.val = close.val := by scalar_tac
      rw [at_end] at so_far
      exact so_far
  · exact ⟨by scalar_tac, ordered, by simp [piece_empty]⟩

/-- `bracket_bad` finds nothing wrong only in an address in brackets, with an optional port. -/
@[step] theorem bracket_bad_accepts_only_addresses (s : Slice Std.U8) (start stop : Std.Usize)
    (opens : (Bytes s.val)[start.val]? = some 91) (nonempty : start.val < stop.val)
    (inside : stop.val ≤ s.length) :
    bracket_bad s start stop ⦃ r => (r = none → IsBracketed (Piece (Bytes s.val) start stop)) ⦄
        := by
  unfold bracket_bad
  step as ⟨ close, close_after, close_before, close_none, close_found ⟩
  split
  · simp only [Std.bind_ok]
    step as ⟨ width, width_post ⟩
    split
    · simp only [Std.bind_ok]
      step as ⟨ first, first_post ⟩
      step as ⟨ inner, inner_post ⟩
      have inner_found : inner ≠ none := fun is_none => by
        have := (inner_post.mp is_none).1
        simp at this
      simp [Option.isNone_iff_eq_none, inner_found]
    · rename_i wide
      simp only [Std.bind_ok]
      step as ⟨ first, first_post ⟩
      step as ⟨ inner, inner_post ⟩
      have inner_found : inner ≠ none := fun is_none => by
        have := (inner_post.mp is_none).1
        simp at this
      simp [Option.isNone_iff_eq_none, inner_found]
  · rename_i not_end
    simp only [Std.bind_ok]
    step as ⟨ width, width_post ⟩
    split
    · simp only [Std.bind_ok]
      step as ⟨ first, first_post ⟩
      step as ⟨ inner, inner_post ⟩
      have inner_found : inner ≠ none := fun is_none => by
        have := (inner_post.mp is_none).1
        simp at this
      simp [Option.isNone_iff_eq_none, inner_found]
    · rename_i wide
      simp only [Std.bind_ok]
      step as ⟨ first, first_post ⟩
      step as ⟨ inner, inner_post ⟩
      have close_lt : close.val < stop.val := by scalar_tac
      have close_at := close_found close_lt
      have wide_enough : start.val + 1 < close.val := by
        have not_one : width.val ≠ 1 := fun is_one => wide (UScalar.eq_of_val_eq
            (by simpa using is_one))
        have not_start : close.val ≠ start.val := fun same => by
          rw [same] at close_at
          simp [opens] at close_at
        scalar_tac
      by_cases unmarked : inner = none
      · simp only [Option.isNone_iff_eq_none, unmarked, ite_true]
        have around := piece_around (Bytes s.val) start close stop 91 93 (by scalar_tac) close_lt
          opens close_at
        have inner_all := inner_post.mp unmarked
        rw [first_post] at inner_all
        step as ⟨ after, after_post ⟩
        split
        · rename_i room
          step as ⟨ colon, colon_post ⟩
          have colon_at := bytes_at s after colon (by scalar_tac) colon_post
          split
          · rename_i is_colon
            step as ⟨ port_start, port_start_post ⟩
            step as ⟨ port, port_post ⟩
            rename_i port_none
            have colon_is : colon.val = 58 := by rw [is_colon]; rfl
            have rest_is : Piece (Bytes s.val) (close.val + 1) stop.val =
                58 :: Piece (Bytes s.val) (close.val + 2) stop.val := by
              rw [piece_cons _ _ _ 58 (by scalar_tac)
                  (by simpa [← after_post, colon_is] using colon_at)]
            refine ⟨Piece (Bytes s.val) (start.val + 1) close.val,
              Piece (Bytes s.val) (close.val + 1) stop.val, by rw [around], ?_, inner_all,
              Or.inr ⟨Piece (Bytes s.val) (close.val + 2) stop.val, rest_is, ?_⟩⟩
            · exact piece_not_empty _ _ _ wide_enough (by simpa using
                (by scalar_tac : close.val ≤ s.length))
            · rw [port_start_post] at port_post
              exact port_post.mp port_none
          · simp
        · rename_i no_room
          simp only [WP.spec_ok]
          intro _
          have rest_empty : Piece (Bytes s.val) (close.val + 1) stop.val = [] := by
            have : close.val + 1 = stop.val := by scalar_tac
            rw [this, piece_empty]
          refine ⟨Piece (Bytes s.val) (start.val + 1) close.val, [], by rw [around, rest_empty],
            ?_, inner_all, Or.inl rfl⟩
          exact piece_not_empty _ _ _ wide_enough (by simpa using
              (by scalar_tac : close.val ≤ s.length))
      · simp [Option.isNone_iff_eq_none, unmarked]

/-- `bracket_bad` finds nothing wrong in every address in brackets, with an optional port. -/
theorem bracket_bad_accepts_every_address (s : Slice Std.U8) (start stop : Std.Usize)
    (nonempty : start.val < stop.val) (inside : stop.val ≤ s.length)
    (is_address : IsBracketed (Piece (Bytes s.val) start stop)) :
    bracket_bad s start stop ⦃ r => r = none ⦄ := by
  obtain ⟨inner, rest, split, inner_filled, inner_ok, rest_ok⟩ := is_address
  have ordered : start.val ≤ stop.val := nonempty.le
  have width := piece_length (Bytes s.val) start stop ordered (by simpa using inside)
  rw [split] at width
  simp only [List.length_append, List.length_singleton] at width
  have inner_long : 0 < inner.length := List.length_pos_iff.mpr inner_filled
  have close_place : start.val + 1 + inner.length < stop.val := by omega
  have inner_piece :
      Piece (Bytes s.val) (start.val + 1) (start.val + 1 + inner.length) = inner := by
    have := piece_middle (Bytes s.val) start stop [91] inner ([93] ++ rest) ordered
      (by simpa using inside) (by rw [split]; simp)
    simpa using this
  have close_at : (Bytes s.val)[start.val + 1 + inner.length]? = some 93 := by
    have := piece_byte (Bytes s.val) start stop (1 + inner.length) 93
      (by rw [split]; simp)
    rwa [← Nat.add_assoc] at this
  have rest_piece : Piece (Bytes s.val) (start.val + 1 + inner.length + 1) stop.val = rest := by
    have := piece_middle (Bytes s.val) start stop ([91] ++ inner ++ [93]) rest [] ordered
      (by simpa using inside) (by rw [split]; simp)
    simp only [List.length_append, List.length_singleton] at this
    rw [show start.val + (1 + inner.length + 1) = start.val + 1 + inner.length + 1 by omega,
      show start.val + 1 + inner.length + 1 + rest.length = stop.val by omega] at this
    exact this
  have head_piece : Piece (Bytes s.val) start (start.val + 1 + inner.length) = [91] ++ inner := by
    have := piece_middle (Bytes s.val) start stop [] ([91] ++ inner) ([93] ++ rest) ordered
      (by simpa using inside) (by rw [split]; simp)
    simpa [Nat.add_assoc, Nat.add_comm] using this
  have close_byte : (93#u8 : Std.U8).val = 93 := rfl
  unfold bracket_bad
  step with find_goes_to_the_first s start stop 93#u8 ordered inside
    (start.val + 1 + inner.length) (by omega) close_place close_at (fun x in_head => by
      rw [head_piece] at in_head
      simp only [List.mem_append, List.mem_singleton] at in_head
      rcases in_head with opens | in_inner
      · omega
      · rcases inner_ok x in_inner with hex | colon
        · unfold IsHex IsDigit at hex; omega
        · omega) as ⟨ close, close_post ⟩
  have close_ne : close ≠ stop := fun same => by rw [same] at close_post; omega
  simp only [close_ne, ↓reduceIte]
  step as ⟨ i, i_post ⟩
  have i_ne : i ≠ 1#usize := fun same => by
    have : i.val = 1 := by rw [same]; rfl
    omega
  simp only [i_ne, ↓reduceIte]
  step as ⟨ first, first_post ⟩
  step with bracket_loop_checks_the_inside s first close none (by scalar_tac) (by scalar_tac)
    as ⟨ inner_bad, inner_bad_post ⟩
  have inner_none : inner_bad = none := by
    refine inner_bad_post.mpr ?_
    rw [first_post, close_post, inner_piece]
    exact inner_ok
  simp only [inner_none, Option.isNone_none, ↓reduceIte]
  step as ⟨ after, after_post ⟩
  split
  · rename_i room
    rcases rest_ok with empty | ⟨port, rest_is, is_port⟩
    · rw [empty] at width
      simp at width
      have : after.val < stop.val := by scalar_tac
      omega
    · step as ⟨ colon, colon_post ⟩
      have colon_at := bytes_at s after colon (by scalar_tac) colon_post
      have after_is : after.val = start.val + 1 + inner.length + 1 := by scalar_tac
      have rest_here : (Bytes s.val)[after.val]? = some 58 := by
        have first_byte : (Piece (Bytes s.val) (start.val + 1 + inner.length + 1) stop.val)[0]? =
            some 58 := by rw [rest_piece, rest_is]; rfl
        have := piece_byte _ _ _ _ _ first_byte
        rw [after_is]; exact this
      rw [rest_here] at colon_at
      have colon_is : colon.val = 58 := (Option.some.inj colon_at).symm
      have is_colon : colon = 58#u8 := UScalar.eq_of_val_eq (by rw [colon_is]; rfl)
      simp only [is_colon, ↓reduceIte]
      step as ⟨ port_start, port_start_post ⟩
      have port_piece : Piece (Bytes s.val) port_start stop = port := by
        have := piece_middle (Bytes s.val) start stop ([91] ++ inner ++ [93] ++ [58]) port []
          ordered (by simpa using inside) (by rw [split, rest_is]; simp)
        simp only [List.length_append, List.length_singleton] at this
        rw [port_start_post, close_post]
        rw [show start.val + (1 + inner.length + 1 + 1) = start.val + 1 + inner.length + 2 by omega,
          show start.val + 1 + inner.length + 2 + port.length = stop.val by
            rw [rest_is] at width; simp at width; omega] at this
        exact this
      step as ⟨ r, r_post ⟩
      exact r_post.mpr (by rw [port_piece]; exact is_port)
  · rename_i no_room
    simp only [WP.spec_ok]

/-- The loop of `domain_bad` reads a domain name from left to right: when it finds nothing wrong,
what it has read is the beginning of a domain name (`DomainSoFar`). -/
@[step] theorem domain_loop_checks_the_labels (s : Slice Std.U8) (start stop : Std.Usize)
    (ordered : start.val ≤ stop.val) (inside : stop.val ≤ s.length) :
    domain_bad_loop s start none stop start ⦃ r =>
      (r = none → DomainSoFar (Piece (Bytes s.val) start stop)) ⦄ := by
  unfold domain_bad_loop
  apply loop.spec_decr_nat (fun (q : Option Std.Usize × Std.Usize) => stop.val - q.2.val)
    (fun (q : Option Std.Usize × Std.Usize) => start.val ≤ q.2.val ∧ q.2.val ≤ stop.val ∧
      (q.1 = none → DomainSoFar (Piece (Bytes s.val) start q.2)))
  · rintro ⟨found, i⟩ ⟨after_start, before_stop, so_far⟩
    simp only at after_start before_stop so_far
    unfold domain_bad_loop.body
    dsimp only
    split
    · rename_i below
      split
      · rename_i unfound
        have unfound' := (is_none_says found).mp unfound
        have state := so_far unfound'
        step as ⟨ x, x_post ⟩
        step as ⟨ alnum, alnum_post ⟩
        have x_at := bytes_at s i x (by scalar_tac) x_post
        have snoc := piece_snoc (Bytes s.val) start i x.val after_start x_at
        split
        · rename_i is_alnum
          simp only [Std.bind_ok]
          step as ⟨ next, next_post ⟩
          refine ⟨by scalar_tac, by scalar_tac, fun _ => ?_, by scalar_tac⟩
          rw [next_post, snoc]
          exact Or.inr (Or.inl (so_far_then_alnum state (alnum_post.mp is_alnum)))
        · rename_i not_alnum
          split
          · rename_i has_prev
            step as ⟨ before, before_post ⟩
            step as ⟨ prev, prev_post ⟩
            have prev_at := bytes_at s before prev (by scalar_tac) prev_post
            have last_is : (Piece (Bytes s.val) start i).getLast? = some prev.val := by
              apply piece_last _ _ _ _ (by scalar_tac)
              rw [← show before.val = i.val - 1 from by scalar_tac]
              exact prev_at
            have filled : Piece (Bytes s.val) start i ≠ [] := fun empty => by
              rw [empty] at last_is; simp at last_is
            split
            · rename_i not_dot
              have not_dot' : prev.val ≠ 46 := (bne_says prev 46#u8).mp not_dot
              step as ⟨ before2, before2_post ⟩
              step as ⟨ prev2, prev2_post ⟩
              have prev2_at := bytes_at s before2 prev2 (by scalar_tac) prev2_post
              have same_place : before2 = before := UScalar.eq_of_val_eq (by scalar_tac)
              rw [same_place, prev_at] at prev2_at
              have same_prev : prev2.val = prev.val := (Option.some.inj prev2_at).symm
              split
              · rename_i is_hyphen
                have x_is : x.val = 45 := by rw [is_hyphen]; rfl
                simp only [Std.bind_ok, not_dot, ite_true]
                step as ⟨ next, next_post ⟩
                refine ⟨by scalar_tac, by scalar_tac, fun _ => ?_, by scalar_tac⟩
                rw [next_post, snoc, x_is]
                exact so_far_then_hyphen state filled (by rw [last_is]; simpa using not_dot')
              · rename_i not_hyphen
                split
                · rename_i is_dot
                  have x_is : x.val = 46 := by rw [is_dot]; rfl
                  simp only [Std.bind_ok]
                  split
                  · rename_i not_hyphen2
                    have not_hyphen' : prev.val ≠ 45 := by
                      rw [← same_prev]; exact (bne_says prev2 45#u8).mp not_hyphen2
                    simp only [Std.bind_ok]
                    step as ⟨ next, next_post ⟩
                    refine ⟨by scalar_tac, by scalar_tac, fun _ => ?_, by scalar_tac⟩
                    rw [next_post, snoc, x_is]
                    exact so_far_then_dot state filled (so_far_last_alnum state filled
                      (by rw [last_is]; simpa using not_dot')
                      (by rw [last_is]; simpa using not_hyphen'))
                  · simp only [Std.bind_ok]
                    step as ⟨ next, next_post ⟩
                    exact ⟨by scalar_tac, by scalar_tac, fun h => by simp at h, by scalar_tac⟩
                · simp only [Std.bind_ok, Bool.false_eq_true, ite_false]
                  step as ⟨ next, next_post ⟩
                  exact ⟨by scalar_tac, by scalar_tac, fun h => by simp at h, by scalar_tac⟩
            · rename_i dot_prev
              simp only [Std.bind_ok, Bool.false_eq_true, ite_false, dot_prev, ite_self]
              step as ⟨ next, next_post ⟩
              exact ⟨by scalar_tac, by scalar_tac, fun h => by simp at h, by scalar_tac⟩
          · simp only [Std.bind_ok, Bool.false_eq_true, ite_false, ite_self]
            step as ⟨ next, next_post ⟩
            exact ⟨by scalar_tac, by scalar_tac, fun h => by simp at h, by scalar_tac⟩
      · rename_i found_one
        simp only [WP.spec_ok]
        intro is_none
        exact absurd ((is_none_says found).mpr is_none) found_one
    · rename_i not_below
      simp only [WP.spec_ok]
      have at_end : i.val = stop.val := by scalar_tac
      rw [at_end] at so_far
      exact so_far
  · exact ⟨by scalar_tac, ordered, fun _ => Or.inl (piece_empty _ _)⟩

/-- The loop of `domain_bad` finds nothing wrong in a piece that begins a domain name. -/
theorem domain_loop_accepts_every_beginning (s : Slice Std.U8) (start stop : Std.Usize)
    (ordered : start.val ≤ stop.val) (inside : stop.val ≤ s.length)
    (so_far : DomainSoFar (Piece (Bytes s.val) start stop)) :
    domain_bad_loop s start none stop start ⦃ r => r = none ⦄ := by
  unfold domain_bad_loop
  apply loop.spec_decr_nat (fun (q : Option Std.Usize × Std.Usize) => stop.val - q.2.val)
    (fun (q : Option Std.Usize × Std.Usize) => start.val ≤ q.2.val ∧ q.2.val ≤ stop.val ∧
      q.1 = none)
  · rintro ⟨found, i⟩ ⟨after_start, before_stop, unfound⟩
    simp only at after_start before_stop unfound
    subst unfound
    unfold domain_bad_loop.body
    dsimp only
    split
    · rename_i below
      simp only [core.option.Option.is_none, Option.isNone_none, ↓reduceIte]
      step as ⟨ x, x_post ⟩
      step as ⟨ alnum, alnum_post ⟩
      have x_at := bytes_at s i x (by scalar_tac) x_post
      -- the piece up to the byte read is still the beginning of a domain name
      have snoc := piece_snoc (Bytes s.val) start i x.val after_start x_at
      have so_far_here : DomainSoFar (Piece (Bytes s.val) start i ++ [x.val]) := by
        rw [← snoc]
        have := so_far_of_a_beginning so_far (i.val + 1 - start.val)
        rwa [piece_take (Bytes s.val) start stop (i.val + 1) (by scalar_tac) (by scalar_tac)]
          at this
      split
      · simp only [Std.bind_ok]
        step as ⟨ next, next_post ⟩
        exact ⟨by scalar_tac, by scalar_tac, by scalar_tac⟩
      · rename_i not_alnum
        have x_not : ¬ IsAlnum x.val := fun a => not_alnum (alnum_post.mpr a)
        obtain ⟨filled, not_dot, kind⟩ := so_far_with_a_separator so_far_here x_not
        have after_start' : start.val < i.val := by
          by_contra not_after
          have same : i.val = start.val := by scalar_tac
          rw [same, piece_empty] at filled
          exact filled rfl
        have after_label : i > start := by scalar_tac
        simp only [after_label, ↓reduceIte]
        step as ⟨ before, before_post ⟩
        step as ⟨ prev, prev_post ⟩
        have prev_at := bytes_at s before prev (by scalar_tac) prev_post
        have last_is : (Piece (Bytes s.val) start i).getLast? = some prev.val := by
          apply piece_last _ _ _ _ after_start'
          rw [← show before.val = i.val - 1 from by scalar_tac]
          exact prev_at
        have prev_not_dot : (prev != 46#u8) = true := by
          rw [bne_says]
          intro same
          exact not_dot (by rw [last_is]; simp [same])
        simp only [prev_not_dot, ↓reduceIte]
        step as ⟨ before2, before2_post ⟩
        step as ⟨ prev2, prev2_post ⟩
        have same_place : before2 = before := UScalar.eq_of_val_eq (by scalar_tac)
        have prev2_at := bytes_at s before2 prev2 (by scalar_tac) prev2_post
        rw [same_place, prev_at] at prev2_at
        have same_prev : prev2.val = prev.val := (Option.some.inj prev2_at).symm
        rcases kind with hyphen | ⟨dot, not_hyphen⟩
        · have is_hyphen : x = 45#u8 := UScalar.eq_of_val_eq (by rw [hyphen]; rfl)
          simp only [is_hyphen, ↓reduceIte, Std.bind_ok]
          step as ⟨ next, next_post ⟩
          exact ⟨by scalar_tac, by scalar_tac, by scalar_tac⟩
        · have is_dot : x = 46#u8 := UScalar.eq_of_val_eq (by rw [dot]; rfl)
          have dot_is_not_hyphen : ¬ ((46#u8 : Std.U8) = 45#u8) := by decide
          have prev_not_hyphen : (prev2 != 45#u8) = true := by
            rw [bne_says, same_prev]
            intro same
            exact not_hyphen (by rw [last_is]; simp [same])
          simp only [is_dot, dot_is_not_hyphen, prev_not_hyphen, ↓reduceIte, Std.bind_ok]
          step as ⟨ next, next_post ⟩
          exact ⟨by scalar_tac, by scalar_tac, by scalar_tac⟩
    · simp only [WP.spec_ok]
  · exact ⟨by scalar_tac, ordered, rfl⟩

/-- `domain_bad` finds nothing wrong in every domain name with an optional port. -/
theorem domain_bad_accepts_every_domain (s : Slice Std.U8) (start stop : Std.Usize)
    (ordered : start.val ≤ stop.val) (inside : stop.val ≤ s.length)
    (is_host : IsDomainHost (Piece (Bytes s.val) start stop)) :
    domain_bad s start stop ⦃ r => r = none ⦄ := by
  obtain ⟨d, rest, is_d, split, rest_ok⟩ : ∃ d rest, Domain d ∧
      Piece (Bytes s.val) start stop = d ++ rest ∧
        (rest = [] ∨ ∃ p, rest = [58] ++ p ∧ IsPort p) := by
    rcases is_host with is_d | ⟨d, p, is_d, is_p, split⟩
    · exact ⟨_, [], is_d, by simp, Or.inl rfl⟩
    · exact ⟨d, [58] ++ p, is_d, by simpa using split, Or.inr ⟨p, rfl, is_p⟩⟩
  have width := piece_length (Bytes s.val) start stop ordered (by simpa using inside)
  rw [split] at width
  simp only [List.length_append] at width
  obtain ⟨d_filled, _, _⟩ := domain_does_not_end_in_a_separator is_d
  have d_long : 0 < d.length := List.length_pos_iff.mpr d_filled
  have d_piece : Piece (Bytes s.val) start (start.val + d.length) = d := by
    have := piece_middle (Bytes s.val) start stop [] d rest ordered (by simpa using inside)
      (by simpa using split)
    simpa using this
  have no_colon : ∀ x ∈ d, x ≠ 58 := fun x in_d is_colon => by
    have := domain_bytes is_d x in_d
    unfold IsAlnum IsLower IsDigit at this
    omega
  have colon_byte : (58#u8 : Std.U8).val = 58 := rfl
  -- the labels end at the first colon, which is after the domain name, or at the end
  have labels_end : find s start stop 58#u8 ⦃ r => r.val = start.val + d.length ⦄ := by
    rcases rest_ok with empty | ⟨p, rest_is, is_p⟩
    · have whole : stop.val = start.val + d.length := by rw [empty] at width; simp at width; omega
      refine WP.spec_mono (find_goes_to_the_end s start stop 58#u8 ordered inside ?_) ?_
      · rw [colon_byte]
        have : Piece (Bytes s.val) start stop = d := by rw [split, empty, List.append_nil]
        rw [this]; exact no_colon
      · intro r is_end; rw [is_end, whole]
    · have rest_piece : (Piece (Bytes s.val) start stop)[d.length]? = some 58 := by
        rw [split, rest_is]; simp
      have colon_at := piece_byte _ _ _ _ _ rest_piece
      have below : start.val + d.length < stop.val := by
        rw [rest_is] at width; simp at width; omega
      exact find_goes_to_the_first s start stop 58#u8 ordered inside (start.val + d.length)
        (by omega) below (by rw [colon_byte]; exact colon_at)
        (by rw [d_piece, colon_byte]; exact no_colon)
  unfold domain_bad
  step with labels_end as ⟨ labels_end, labels_end_post ⟩
  have whole_domain : Piece (Bytes s.val) start labels_end = d := by
    rw [labels_end_post]; exact d_piece
  step with domain_loop_accepts_every_beginning s start labels_end (by scalar_tac)
    (by scalar_tac) (by rw [whole_domain]; exact Or.inr (Or.inl is_d)) as ⟨ bad, bad_post ⟩
  simp only [bad_post, Option.isSome_none, Bool.false_eq_true, ↓reduceIte]
  have not_start : labels_end ≠ start := fun same => by
    rw [same] at labels_end_post; omega
  simp only [not_start, ↓reduceIte]
  step as ⟨ before, before_post ⟩
  step as ⟨ last, last_post ⟩
  step as ⟨ alnum, alnum_post ⟩
  have last_at := bytes_at s before last (by scalar_tac) last_post
  obtain ⟨z, z_is, z_alnum⟩ := domain_ends_in_alnum is_d
  have last_is : (Piece (Bytes s.val) start labels_end).getLast? = some z := by
    rw [whole_domain]; exact z_is
  have z_at := piece_last_byte (Bytes s.val) start labels_end z (by omega) (by simpa using
    (by scalar_tac : labels_end.val ≤ s.length)) last_is
  rw [← show before.val = labels_end.val - 1 from by scalar_tac, last_at] at z_at
  have last_val : last.val = z := (Option.some.inj z_at)
  have is_alnum : alnum = true := alnum_post.mpr (by rw [last_val]; exact z_alnum)
  simp only [is_alnum, ↓reduceIte]
  split
  · rename_i has_port
    rcases rest_ok with empty | ⟨p, rest_is, is_p⟩
    · rw [empty] at width; simp at width; scalar_tac
    · step as ⟨ port_start, port_start_post ⟩
      have port_piece : Piece (Bytes s.val) port_start stop = p := by
        have := piece_middle (Bytes s.val) start stop (d ++ [58]) p [] ordered
          (by simpa using inside) (by rw [split, rest_is]; simp)
        simp only [List.length_append, List.length_singleton] at this
        rw [show start.val + (d.length + 1) + p.length = stop.val by
            rw [rest_is] at width; simp at width; omega,
          ← Nat.add_assoc] at this
        rw [port_start_post, labels_end_post]
        exact this
      step as ⟨ r, r_post ⟩
      exact r_post.mpr (by rw [port_piece]; exact is_p)
  · simp only [WP.spec_ok]

/-- `domain_bad` finds nothing wrong only in a domain name with an optional port. -/
@[step] theorem domain_bad_accepts_only_domains (s : Slice Std.U8) (start stop : Std.Usize)
    (ordered : start.val ≤ stop.val) (inside : stop.val ≤ s.length) :
    domain_bad s start stop ⦃ r => (r = none → IsDomainHost (Piece (Bytes s.val) start stop)) ⦄
        := by
  unfold domain_bad
  step as ⟨ labels_end, labels_after, labels_before, labels_none, labels_found ⟩
  step as ⟨ bad, bad_post ⟩
  by_cases marked : bad = none
  · simp only [marked, Option.isSome_none, Bool.false_eq_true, ite_false]
    have state := bad_post marked
    split
    · simp
    · rename_i not_empty
      step as ⟨ before, before_post ⟩
      step as ⟨ last, last_post ⟩
      step as ⟨ alnum, alnum_post ⟩
      split
      · rename_i is_alnum
        have not_at_start : start.val < labels_end.val := by
          have : labels_end ≠ start := not_empty
          scalar_tac
        have last_at := bytes_at s before last (by scalar_tac) last_post
        have before_is : before.val = labels_end.val - 1 := by scalar_tac
        have last_is : (Piece (Bytes s.val) start labels_end).getLast? = some last.val :=
          piece_last _ _ _ _ not_at_start (by rw [← before_is]; exact last_at)
        have filled : Piece (Bytes s.val) start labels_end ≠ [] := fun empty => by
          rw [empty] at last_is; simp at last_is
        have is_domain : Domain (Piece (Bytes s.val) start labels_end) :=
          so_far_alnum_last state filled ⟨last.val, last_is, alnum_post.mp is_alnum⟩
        split
        · rename_i has_port
          step as ⟨ port_start, port_start_post ⟩
          step as ⟨ port, port_post ⟩
          rename_i port_none
          have colon_at := labels_found (by scalar_tac)
          have split_piece : Piece (Bytes s.val) start stop = Piece
              (Bytes s.val) start labels_end ++
              [58] ++ Piece (Bytes s.val) (labels_end.val + 1) stop := by
            rw [piece_append _ start labels_end stop labels_after labels_before,
              piece_cons _ labels_end stop 58 (by scalar_tac) colon_at]
            simp
          rw [split_piece]
          rw [port_start_post] at port_post
          exact Or.inr ⟨_, _, is_domain, port_post.mp port_none, rfl⟩
        · rename_i no_port
          simp only [WP.spec_ok]
          intro _
          have whole : labels_end.val = stop.val := by scalar_tac
          rw [← whole]
          exact Or.inl is_domain
      · simp
  · have marked' : bad ≠ none := marked
    have : bad.isSome = true := by
      cases bad with
      | none => exact absurd rfl marked
      | some _ => rfl
    simp only [this, ite_true, WP.spec_ok]
    exact fun h => absurd h marked

/-- `host_bad` finds nothing wrong only in a host of the grammar. -/
@[step] theorem host_bad_accepts_only_hosts (s : Slice Std.U8) (start stop : Std.Usize)
    (ordered : start.val ≤ stop.val) (inside : stop.val ≤ s.length) :
    host_bad s start stop ⦃ r => (r = none → IsHost (Piece (Bytes s.val) start stop)) ⦄ := by
  unfold host_bad
  split
  · simp
  · rename_i not_empty
    step as ⟨ first, first_post ⟩
    have first_at := bytes_at s start first (by scalar_tac) first_post
    have below : start.val < stop.val := by
      have : start ≠ stop := not_empty
      scalar_tac
    split
    · rename_i is_bracket
      have opens : (Bytes s.val)[start.val]? = some 91 := by
        rw [first_at, is_bracket]; rfl
      step as ⟨ r, r_post ⟩
      rename_i is_none
      exact Or.inl (r_post is_none)
    · step as ⟨ r, r_post ⟩
      rename_i is_none
      exact Or.inr (r_post is_none)

/-- A domain name with an optional port has no `[`. -/
theorem domain_host_has_no_bracket {h : List Nat} (is_host : IsDomainHost h) : ∀ b ∈ h, b ≠ 91 := by
  intro b inside is_bracket
  have bytes : IsAlnum b ∨ b = 45 ∨ b = 46 ∨ b = 58 ∨ IsDigit b := by
    rcases is_host with domain | ⟨d, p, is_d, is_p, split⟩
    · rcases domain_bytes domain b inside with a | h | d
      · exact Or.inl a
      · exact Or.inr (Or.inl h)
      · exact Or.inr (Or.inr (Or.inl d))
    · rw [split] at inside
      simp only [List.mem_append, List.mem_singleton] at inside
      rcases inside with (in_d | colon) | in_p
      · rcases domain_bytes is_d b in_d with a | h | d
        · exact Or.inl a
        · exact Or.inr (Or.inl h)
        · exact Or.inr (Or.inr (Or.inl d))
      · exact Or.inr (Or.inr (Or.inr (Or.inl colon)))
      · exact Or.inr (Or.inr (Or.inr (Or.inr (is_p.2 b in_p))))
  unfold IsAlnum IsLower IsDigit at bytes
  omega

/-- `host_bad` finds nothing wrong in every host of the grammar. -/
theorem host_bad_accepts_every_host (s : Slice Std.U8) (start stop : Std.Usize)
    (ordered : start.val ≤ stop.val) (inside : stop.val ≤ s.length)
    (is_host : IsHost (Piece (Bytes s.val) start stop)) :
    host_bad s start stop ⦃ r => r = none ⦄ := by
  have below : start.val < stop.val := by
    by_contra not_below
    have same : stop.val = start.val := by scalar_tac
    rw [same, piece_empty] at is_host
    rcases is_host with ⟨inner, rest, split, _⟩ | domain | ⟨d, p, is_d, _, split⟩
    · simp at split
    · rcases domain_cases (by simpa using domain) with is_label | ⟨d, lab, _, is_label, split⟩
      · obtain ⟨_, ⟨b, b_is, _⟩, _⟩ := is_label; simp at b_is
      · simp at split
    · simp at split
  have first_in : (Piece (Bytes s.val) start stop)[0]? = (Bytes s.val)[start.val]? := by
    simp only [piece_get, show 0 < stop.val - start.val by omega, ↓reduceIte]; simp
  unfold host_bad
  split
  · rename_i empty
    have : start.val = stop.val := by rw [empty]
    omega
  · step as ⟨ first, first_post ⟩
    have first_at := bytes_at s start first (by scalar_tac) first_post
    split
    · rename_i is_bracket
      exact bracket_bad_accepts_every_address s start stop below inside (by
        rcases is_host with address | domain
        · exact address
        · exfalso
          have := domain_host_has_no_bracket domain first.val (by
            have in_piece := piece_contains (Bytes s.val) start stop start.val first.val
              (le_refl _) below first_at
            exact in_piece)
          exact this (by rw [is_bracket]; rfl))
    · rename_i not_bracket
      refine domain_bad_accepts_every_domain s start stop ordered inside ?_
      rcases is_host with ⟨inner, rest, split, _⟩ | domain
      · exfalso
        have : (Piece (Bytes s.val) start stop)[0]? = some 91 := by rw [split]; simp
        rw [first_in, first_at] at this
        exact not_bracket (UScalar.eq_of_val_eq (Option.some.inj this))
      · exact domain

end RefCore
