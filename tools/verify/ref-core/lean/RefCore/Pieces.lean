-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: small facts about `Piece text start stop`, the bytes of a text from a
-- place up to another (Spec.lean): its length, one byte more at its end, a piece cut in two, the
-- first byte of a piece, and the facts that the loops that look for a bad byte are made of. It
-- also shows how a piece is cut when the string is three lists one after the other.
-- Why it is needed: every loop of the crate goes through a string place by place, and each proof
-- says what it has seen as a piece; these facts are how the piece grows by one byte.
-- Read before this file: Spec.lean (`Piece`, `Bytes`).
-- Notation: `l ++ l'` is `l` and then `l'`; `x ∈ l` is "x is in l"; `text[i]? = some x` is "the
-- byte at the place i of the text is x"; `l.getLast?` is the last byte of `l`, if it has one.
import RefCore.Spec
open Aeneas Aeneas.Std Result velarx_ref_core
namespace RefCore

/-- The bytes of a slice as numbers have the length of the slice. -/
@[simp] theorem bytes_length (l : List Std.U8) : (Bytes l).length = l.length := by
  simp [Bytes]

/-- The byte at a place of a slice, as a number. -/
theorem bytes_get (l : List Std.U8) (i : Nat) (x : Std.U8) (there : l[i]? = some x) :
    (Bytes l)[i]? = some x.val := by
  simp [Bytes, there]

/-- Nothing is between a place and itself. -/
theorem piece_empty (text : List Nat) (start : Nat) : Piece text start start = [] := by
  simp [Piece]

/-- One more byte after a piece is the piece up to the next place. -/
theorem piece_snoc (text : List Nat) (start stop x : Nat) (_after : start ≤ stop)
    (there : text[stop]? = some x) : Piece text start (stop + 1) = Piece text start stop ++ [x]
        := by
  have width : stop + 1 - start = (stop - start) + 1 := by omega
  have place : start + (stop - start) = stop := by omega
  simp only [Piece, width, List.take_add_one, List.getElem?_drop, place, there]
  rfl

/-- A piece between two places of a text has the length between them. -/
theorem piece_length (text : List Nat) (start stop : Nat) (_after : start ≤ stop)
    (inside : stop ≤ text.length) : (Piece text start stop).length = stop - start := by
  simp [Piece]
  omega

/-- The beginning of a piece is the piece up to an earlier place. -/
theorem piece_take (text : List Nat) (start stop mid : Nat) (before : start ≤ mid)
    (earlier : mid ≤ stop) : (Piece text start stop).take (mid - start) = Piece text start mid := by
  simp only [Piece, List.take_take]
  congr 1
  omega

/-- A piece is the piece up to a place in it, and the piece from there. -/
theorem piece_append (text : List Nat) (start mid stop : Nat) (before : start ≤ mid)
    (earlier : mid ≤ stop) : Piece text start stop = Piece text start mid ++ Piece text mid stop
        := by
  simp only [Piece]
  have width : stop - start = (mid - start) + (stop - mid) := by omega
  rw [width, List.take_add, List.drop_drop]
  congr 3
  omega

/-- A piece of one byte. -/
theorem piece_one (text : List Nat) (place x : Nat) (there : text[place]? = some x) :
    Piece text place (place + 1) = [x] := by
  have := piece_snoc text place place x (le_refl _) there
  rwa [piece_empty, List.nil_append] at this

/-- The last byte of a piece that is not empty is the byte before its end. -/
theorem piece_last (text : List Nat) (start stop x : Nat) (before : start < stop)
    (there : text[stop - 1]? = some x) : (Piece text start stop).getLast? = some x := by
  have snoc := piece_snoc text start (stop - 1) x (by omega) there
  rw [show stop - 1 + 1 = stop by omega] at snoc
  rw [snoc]
  simp

/-- The piece from the first place to the last is the whole text. -/
theorem piece_whole (text : List Nat) : Piece text 0 text.length = text := by
  simp [Piece]

/-- A piece that begins with a byte is that byte and the piece after it. -/
theorem piece_cons (text : List Nat) (start stop x : Nat) (before : start < stop)
    (there : text[start]? = some x) : Piece text start stop = x :: Piece text (start + 1) stop := by
  rw [piece_append text start (start + 1) stop (by omega) before, piece_one text start x there]
  rfl

/-- A byte of the text between two places is in the piece between them. -/
theorem piece_contains (text : List Nat) (start stop place x : Nat) (after : start ≤ place)
    (before : place < stop) (there : text[place]? = some x) : x ∈ Piece text start stop := by
  rw [piece_append text start place stop after before.le,
    piece_cons text place stop x before there]
  simp

/-- A piece between two bytes that are in it: the first byte, what is between, the second byte and
what follows. -/
theorem piece_around (text : List Nat) (start mid stop a b : Nat) (first : start < mid)
    (second : mid < stop) (first_is : text[start]? = some a) (second_is : text[mid]? = some b) :
    Piece text start stop = [a] ++ Piece text (start + 1) mid ++ [b] ++ Piece text (mid + 1) stop
        := by
  rw [piece_cons text start stop a (by omega) first_is,
    piece_append text (start + 1) mid stop (by omega) (by omega),
    piece_cons text mid stop b second second_is]
  simp

/-- What is in a piece is in a longer piece with the same beginning. -/
theorem piece_mem_of_shorter (text : List Nat) (start mid stop x : Nat) (before : start ≤ mid)
    (earlier : mid ≤ stop) (found : x ∈ Piece text start mid) : x ∈ Piece text start stop := by
  rw [← piece_take text start stop mid before earlier] at found
  exact List.mem_of_mem_take found

/-- A fact about every byte of a list and one byte more is a fact about the list and the byte. -/
theorem forall_snoc (l : List Nat) (y : Nat) (P : Nat → Prop) :
    (∀ x ∈ l ++ [y], P x) ↔ (∀ x ∈ l, P x) ∧ P y := by
  simp only [List.mem_append, List.mem_singleton]
  constructor
  · exact fun all => ⟨fun x inside => all x (Or.inl inside), all y (Or.inr rfl)⟩
  · rintro ⟨old, new⟩ x (inside | same)
    · exact old x inside
    · rw [same]; exact new

/-- The byte `x` that Rust reads at the place `i` of a slice is the number at that place of
`Bytes`. -/
theorem bytes_at (s : Slice Std.U8) (i : Std.Usize) (x : Std.U8) (inside : i.val < s.length)
    (read : x = s.val[i.val]) : (Bytes s.val)[i.val]? = some x.val := by
  simp [Bytes, read, inside]

/-- Two bytes differ (`!=`) exactly when their numbers do. -/
theorem bne_says (x y : Std.U8) : (x != y) = true ↔ x.val ≠ y.val := by
  simp [UScalar.eq_equiv]

/-- Two bytes are equal exactly when their numbers are. -/
theorem eq_says (x y : Std.U8) : (x = y) ↔ x.val = y.val := UScalar.eq_equiv x y

/-! The three facts the loops that look for the first bad byte of a piece are made of.  Such a
loop carries `found`, the place of a bad byte if it has seen one; the invariant is "`found` is
`none` exactly when nothing was wrong before the loop and every byte so far is good". -/

/-- A good byte keeps the invariant. -/
theorem scan_good_byte (found : Option Std.Usize) (before : Prop) (seen : List Nat) (y : Nat)
    (good : Nat → Prop) (invariant : found = none ↔ before ∧ ∀ x ∈ seen, good x)
    (unfound : found = none) (is_good : good y) :
    found = none ↔ before ∧ ∀ x ∈ seen ++ [y], good x := by
  rw [forall_snoc]
  simp only [unfound, true_iff] at invariant ⊢
  exact ⟨invariant.1, invariant.2, is_good⟩

/-- A bad byte is a place where the invariant says "found". -/
theorem scan_bad_byte (place : Std.Usize) (before : Prop) (seen : List Nat) (y : Nat)
    (good : Nat → Prop) (is_bad : ¬ good y) :
    (some place = none) ↔ before ∧ ∀ x ∈ seen ++ [y], good x := by
  rw [forall_snoc]
  simp only [reduceCtorEq, false_iff, not_and]
  exact fun _ _ is_it => is_bad is_it

/-- When a bad byte was found before, the loop is over: nothing in the whole piece is wrong
exactly when it was not wrong before the part that was seen. -/
theorem scan_stops (found : Option Std.Usize) (before : Prop) (text : List Nat)
    (start mid stop : Nat) (good : Nat → Prop) (after_start : start ≤ mid)
        (before_stop : mid ≤ stop)
    (invariant : found = none ↔ before ∧ ∀ x ∈ Piece text start mid, good x)
    (found_one : found ≠ none) :
    found = none ↔ before ∧ ∀ x ∈ Piece text start stop, good x :=
  ⟨fun is_none => absurd is_none found_one, fun ⟨unmarked, all⟩ => absurd (invariant.mpr ⟨unmarked,
    fun x inside => all x (piece_mem_of_shorter _ _ _ _ _ after_start before_stop inside)⟩)
    found_one⟩

/-- What comes before the first byte `x` of a list, when it is there, is what `takeWhile` takes. -/
theorem take_before_the_byte (before after : List Nat) (x : Nat)
    (none_before : ∀ y ∈ before, y ≠ x) :
    (before ++ x :: after).takeWhile (· ≠ x) = before := by
  induction before with
  | nil => simp
  | cons head rest ih =>
    have head_ne := none_before head (by simp)
    have rest_ne : ∀ y ∈ rest, y ≠ x := fun y inside => none_before y (by simp [inside])
    have := ih rest_ne
    simpa [List.takeWhile_cons, head_ne] using this

/-- The byte at a place of a piece is the byte of the text that many places after its start. -/
theorem piece_get (text : List Nat) (start stop k : Nat) :
    (Piece text start stop)[k]? = if k < stop - start then text[start + k]? else none := by
  simp only [Piece, List.getElem?_take, List.getElem?_drop]

/-- The first byte of a piece that is not empty is the byte of the text at its start. -/
theorem piece_head (text : List Nat) (start stop x : Nat) (before : start < stop)
    (first : (Piece text start stop).head? = some x) : text[start]? = some x := by
  have := piece_get text start stop 0
  have positive : 0 < stop - start := by omega
  simp only [positive, ↓reduceIte, Nat.add_zero] at this
  rw [List.head?_eq_getElem?] at first
  rw [first] at this
  exact this.symm

/-- A byte of the text at a place of a piece, when the piece is cut in two there. -/
theorem piece_before_the_byte (text : List Nat) (start stop place x : Nat) (after : start ≤ place)
    (before : place < stop) (there : text[place]? = some x) :
    (Piece text start stop)[place - start]? = some x := by
  have width : place - start < stop - start := by omega
  simp only [piece_get, width, ↓reduceIte, show start + (place - start) = place by omega, there]

/-- A piece of the whole text, when the text is three lists one after the other, is the middle
one. -/
theorem piece_of_the_middle (before middle after : List Nat) :
    Piece (before ++ middle ++ after) before.length (before.length + middle.length) = middle := by
  simp [Piece]

/-- A byte of a piece is the byte of the text that many places after the start of the piece. -/
theorem piece_byte (text : List Nat) (start stop k x : Nat)
    (there : (Piece text start stop)[k]? = some x) : text[start + k]? = some x := by
  rw [piece_get] at there
  split at there
  · exact there
  · simp at there

/-- A piece that is three lists one after the other has the middle one between its places. -/
theorem piece_middle (text : List Nat) (start stop : Nat) (before middle after : List Nat)
    (ordered : start ≤ stop) (inside : stop ≤ text.length)
    (cut : Piece text start stop = before ++ middle ++ after) :
    Piece text (start + before.length) (start + before.length + middle.length) = middle := by
  have width := piece_length text start stop ordered inside
  rw [cut] at width
  simp only [List.length_append] at width
  have sub : Piece text (start + before.length) (start + before.length + middle.length) =
      ((Piece text start stop).drop before.length).take middle.length := by
    have fits : middle.length ≤ stop - start - before.length := by omega
    simp only [Piece, List.drop_take, List.drop_drop, List.take_take, Nat.add_sub_cancel_left,
      Nat.min_eq_left fits]
  rw [sub, cut]
  simp

/-- The byte before the end of a piece that is not empty is the last byte of the piece. -/
theorem piece_last_byte (text : List Nat) (start stop z : Nat) (before : start < stop)
    (inside : stop ≤ text.length) (last : (Piece text start stop).getLast? = some z) :
    text[stop - 1]? = some z := by
  rw [List.getLast?_eq_getElem?, piece_length text start stop before.le inside] at last
  have := piece_byte text start stop (stop - start - 1) z last
  rwa [show start + (stop - start - 1) = stop - 1 by omega] at this

/-- When the bytes of a string are three lists one after the other, the piece between the places
where the first ends and where the second ends is the second. -/
theorem piece_of_the_parts (s : Slice Std.U8) (before middle after : List Nat) (a b : Nat)
    (text : before ++ middle ++ after = Bytes s.val) (a_is : a = before.length)
    (b_is : b = before.length + middle.length) :
    Piece (Bytes s.val) a b = middle := by
  rw [a_is, b_is]
  have := piece_middle (Bytes s.val) 0 s.length before middle after (Nat.zero_le _)
    (by simp) (by
      have whole := piece_whole (Bytes s.val)
      simp only [bytes_length] at whole
      rw [whole, ← text])
  simpa using this

end RefCore
