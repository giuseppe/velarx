-- SPDX-License-Identifier: Apache-2.0
-- What this file shows: what `path_bad` does: when it finds nothing wrong, the bytes are a path of
-- the grammar (`Path`): components joined by `/`.  And what `host_like` says: a piece looks like a
-- host exactly when it has a `.` or a `:` or is `localhost` (`LooksLikeHost`). It also shows the
-- other direction: `path_bad` finds nothing wrong in every path of the grammar.
-- Why it is needed: these are the last two checks that `parse` needs before it can be followed.
-- Read before this file: Components.lean.
-- Notation: `PathInvariant` is what the loop keeps true: where the component being read began and
-- that what is before it is a path ended by a `/`.
import RefCore.Components
open Aeneas Aeneas.Std Result velarx_ref_core
namespace RefCore

/-- What is left of a path while it is read from left to right: a component, or a component, a `/`
and what is left. -/
inductive PathRest : List Nat → Prop
  | last {c : List Nat} : Component c → PathRest c
  | step {c rest : List Nat} : Component c → PathRest rest → PathRest (c ++ 47 :: rest)

/-- What is left is a component, or a component, a `/` and what is left. -/
theorem path_rest_cases {l : List Nat} (rest : PathRest l) :
    Component l ∨ ∃ c r, Component c ∧ PathRest r ∧ l = c ++ 47 :: r := by
  cases rest with
  | last is_component => exact Or.inl is_component
  | step is_component more => exact Or.inr ⟨_, _, is_component, more, rfl⟩

/-- A path, with a `/` and a component after it, is still what can be read. -/
theorem path_rest_then_a_component {l c : List Nat} (rest : PathRest l)
    (is_component : Component c) : PathRest (l ++ 47 :: c) := by
  induction rest with
  | last first => exact PathRest.step first (PathRest.last is_component)
  | step first more ih =>
    rw [List.append_assoc]
    exact PathRest.step first ih

/-- A path of the grammar is what can be read. -/
theorem path_is_what_can_be_read {p : List Nat} (is_path : Path p) : PathRest p := by
  induction is_path with
  | one is_component => exact PathRest.last is_component
  | more old is_component ih =>
    rw [List.append_assoc]
    exact path_rest_then_a_component ih is_component

/-- A component has no `/`. -/
theorem component_has_no_slash {c : List Nat} (is_component : Component c) : ∀ b ∈ c, b ≠ 47 := by
  intro b inside is_slash
  have := (component_shape is_component).2 b inside
  unfold IsAlnum IsLower IsDigit at this
  omega

/-- What the loop of `path_bad` keeps true when it is at the place `i` and the component it reads
began at `begins`: no `/` since then, and what is before it is a path ended by a `/`
(or nothing is, and it is the first component). -/
def PathInvariant (text : List Nat) (start stop : Nat) (begins i : Nat) : Prop :=
  start ≤ begins ∧ begins ≤ i ∧ i ≤ stop + 1 ∧ (stop + 1 ≤ i → begins = i) ∧
    (∀ x ∈ Piece text begins i, x ≠ 47) ∧
    (begins = start ∨ (start < begins ∧ Path (Piece text start (begins - 1)) ∧
      (begins - 1 < stop → text[begins - 1]? = some 47)))

/-- A component, ended by the end of the path or by a `/`, makes the path of what was read. -/
theorem path_after_a_component (text : List Nat) (start stop begins i : Nat)
    (invariant : PathInvariant text start stop begins i) (component : Component
        (Piece text begins i))
    (ends_here : i = stop ∨ text[i]? = some 47) (not_past : i ≤ stop) :
    PathInvariant text start stop (i + 1) (i + 1) := by
  obtain ⟨after_start, begins_le, _, _, _, shape⟩ := invariant
  refine ⟨by omega, le_refl _, by omega, fun _ => rfl, by simp [piece_empty], Or.inr
      ⟨by omega, ?_, ?_⟩⟩
  · simp only [Nat.add_sub_cancel]
    rcases shape with first | ⟨later, before, slash⟩
    · rw [first] at component
      exact Path.one component
    · have slash' := slash (by omega)
      rw [piece_append text start (begins - 1) i (by omega) (by omega),
        show Piece text (begins - 1) i = [47] ++ Piece text begins i from by
          rw [piece_cons text (begins - 1) i 47 (by omega) slash', show begins - 1 + 1 = begins
              by omega]
          rfl]
      simpa [List.append_assoc] using Path.more before component
  · intro below
    simp only [Nat.add_sub_cancel]
    rcases ends_here with same | slash
    · omega
    · exact slash

/-- The loop of `path_bad` reads the components from left to right: when it finds nothing wrong,
what it has read is a path of the grammar. -/
@[step] theorem path_loop_checks_the_components (s : Slice Std.U8) (start stop : Std.Usize)
    (ordered : start.val ≤ stop.val) (inside : stop.val ≤ s.length)
    (room : stop.val + 8 ≤ Usize.max) :
    path_bad_loop s stop none start start ⦃ r =>
      (r = none → Path (Piece (Bytes s.val) start stop)) ⦄ := by
  unfold path_bad_loop
  apply loop.spec_decr_nat
    (fun (q : Option Std.Usize × Std.Usize × Std.Usize) => stop.val + 1 - q.2.2.val)
    (fun (q : Option Std.Usize × Std.Usize × Std.Usize) =>
      q.1 = none → PathInvariant (Bytes s.val) start stop q.2.1 q.2.2)
  · rintro ⟨found, begins, i⟩ so_far
    simp only at so_far
    unfold path_bad_loop.body
    dsimp only
    split
    · rename_i in_loop
      split
      · rename_i unfound
        have unfound' := (is_none_says found).mp unfound
        have invariant := so_far unfound'
        obtain ⟨after_start, begins_le, i_le, ended, no_slash, shape⟩ := invariant
        have i_le_stop : i.val ≤ stop.val := by scalar_tac
        split
        · rename_i at_end
          step as ⟨ bad2, bad2_post ⟩
          step as ⟨ next_begins, next_begins_post ⟩
          step as ⟨ next, next_post ⟩
          refine ⟨fun is_none => ?_, by scalar_tac⟩
          rw [next_begins_post, next_post]
          exact path_after_a_component _ _ _ _ _ ⟨after_start, begins_le, i_le, ended,
            no_slash, shape⟩ (bad2_post is_none) (Or.inl (by scalar_tac)) i_le_stop
        · rename_i not_end
          have below : i.val < stop.val := by
            have : i ≠ stop := not_end
            scalar_tac
          step as ⟨ x, x_post ⟩
          have x_at := bytes_at s i x (by scalar_tac) x_post
          split
          · rename_i is_slash
            have slash_at : (Bytes s.val)[i.val]? = some 47 := by
              rw [x_at, is_slash]; rfl
            step as ⟨ bad2, bad2_post ⟩
            step as ⟨ next_begins, next_begins_post ⟩
            step as ⟨ next, next_post ⟩
            refine ⟨fun is_none => ?_, by scalar_tac⟩
            rw [next_begins_post, next_post]
            exact path_after_a_component _ _ _ _ _ ⟨after_start, begins_le, i_le, ended,
              no_slash, shape⟩ (bad2_post is_none) (Or.inr slash_at) i_le_stop
          · rename_i not_slash
            simp only [Std.bind_ok]
            step as ⟨ next, next_post ⟩
            refine ⟨fun _ => ⟨after_start, by scalar_tac, by scalar_tac, fun h => by scalar_tac, ?_,
              shape⟩, by scalar_tac⟩
            rw [next_post, piece_snoc _ _ _ _ begins_le x_at]
            intro y y_in
            rcases List.mem_append.mp y_in with old | new
            · exact no_slash y old
            · rw [List.mem_singleton.mp new]
              exact fun same => not_slash (by rw [eq_says]; exact same)
      · rename_i found_one
        simp only [WP.spec_ok]
        intro is_none
        exact absurd ((is_none_says found).mpr is_none) found_one
    · rename_i not_in_loop
      simp only [WP.spec_ok]
      intro is_none
      obtain ⟨after_start, begins_le, i_le, ended, no_slash, shape⟩ := so_far is_none
      have at_end : begins.val = stop.val + 1 := by
        have := ended (by scalar_tac)
        scalar_tac
      rcases shape with first | ⟨later, path, _⟩
      · scalar_tac
      · rw [at_end] at path
        simpa using path
  · intro _
    refine ⟨le_refl _, le_refl _, by scalar_tac, fun h => by scalar_tac, by simp [piece_empty],
      Or.inl rfl⟩

/-- What the loop of `path_bad` keeps true when no component was wrong: the loop is over, or the
component read so far has no `/` and what is left is what can be read. -/
def PathReadable (text : List Nat) (stop : Nat) (begins i : Nat) : Prop :=
  i = stop + 1 ∨ (begins ≤ i ∧ i ≤ stop ∧ PathRest (Piece text begins stop) ∧
    ∀ x ∈ Piece text begins i, x ≠ 47)

/-- The first component of what is left, with what follows it: nothing, or a `/` and what is
left. -/
theorem path_rest_has_a_first_component (text : List Nat) (begins stop : Nat)
    (rest : PathRest (Piece text begins stop)) :
    ∃ c after, Piece text begins stop = c ++ after ∧ Component c ∧
      (after = [] ∨ ∃ r, after = 47 :: r ∧ PathRest r) := by
  rcases path_rest_cases rest with is_component | ⟨c, r, is_component, more, is_cut⟩
  · exact ⟨_, [], by simp, is_component, Or.inl rfl⟩
  · exact ⟨c, 47 :: r, is_cut, is_component, Or.inr ⟨r, rfl, more⟩⟩

/-- The loop of `path_bad` finds nothing wrong in what can be read as a path. -/
theorem path_loop_accepts_every_path (s : Slice Std.U8) (start stop : Std.Usize)
    (ordered : start.val ≤ stop.val) (inside : stop.val ≤ s.length)
    (room : stop.val + 8 ≤ Usize.max) (readable : PathRest (Piece (Bytes s.val) start stop)) :
    path_bad_loop s stop none start start ⦃ r => r = none ⦄ := by
  unfold path_bad_loop
  apply loop.spec_decr_nat
    (fun (q : Option Std.Usize × Std.Usize × Std.Usize) => stop.val + 1 - q.2.2.val)
    (fun (q : Option Std.Usize × Std.Usize × Std.Usize) => q.1 = none ∧
      PathReadable (Bytes s.val) stop.val q.2.1.val q.2.2.val)
  · rintro ⟨found, begins, i⟩ ⟨unfound, state⟩
    simp only at unfound state
    subst unfound
    unfold path_bad_loop.body
    dsimp only
    split
    · rename_i in_loop
      have i_le : i.val ≤ stop.val := by scalar_tac
      simp only [core.option.Option.is_none, Option.isNone_none, ↓reduceIte]
      obtain ⟨begins_le, _, rest, no_slash⟩ : begins.val ≤ i.val ∧ i.val ≤ stop.val ∧
          PathRest (Piece (Bytes s.val) begins stop) ∧
          ∀ x ∈ Piece (Bytes s.val) begins i, x ≠ 47 := by
        rcases state with past | here
        · omega
        · exact here
      obtain ⟨c, after, cut, is_c, kind⟩ := path_rest_has_a_first_component _ _ _ rest
      have width := piece_length (Bytes s.val) begins stop (by omega) (by simpa using inside)
      rw [cut] at width
      simp only [List.length_append] at width
      -- the component ends at `begins + c.length`; the loop does not go past it
      have boundary_le : begins.val + c.length ≤ stop.val := by omega
      have c_piece : Piece (Bytes s.val) begins (begins.val + c.length) = c := by
        have := piece_middle (Bytes s.val) begins stop [] c after (by omega)
          (by simpa using inside) (by rw [cut, List.nil_append])
        simpa using this
      have not_past : i.val ≤ begins.val + c.length := by
        by_contra past
        rcases kind with empty | ⟨r, after_is, _⟩
        · rw [empty] at width; simp at width; omega
        · have slash_at : (Bytes s.val)[begins.val + c.length]? = some 47 := by
            have := piece_byte (Bytes s.val) begins stop c.length 47 (by rw [cut, after_is]; simp)
            exact this
          exact no_slash 47 (piece_contains _ _ _ (begins.val + c.length) 47 (by omega)
            (by omega) slash_at) rfl
      -- a byte of the component is not a `/`
      have inside_c : ∀ x, i.val < begins.val + c.length → (Bytes s.val)[i.val]? = some x →
          x ≠ 47 := by
        intro x short x_at
        apply component_has_no_slash is_c x
        rw [← c_piece]
        exact piece_contains _ _ _ i.val x (by omega) short x_at
      split
      · rename_i at_end
        have at_boundary : i.val = begins.val + c.length := by
          have i_is : i.val = stop.val := by scalar_tac
          rcases kind with empty | ⟨r, after_is, _⟩
          · rw [empty] at width; simp at width; omega
          · rw [after_is] at width; simp at width; omega
        have c_here : Component (Piece (Bytes s.val) begins i) := by
          rw [at_boundary, c_piece]; exact is_c
        step with component_bad_accepts_every_component s begins i begins_le (by omega)
          c_here as ⟨ bad2, bad2_post ⟩
        step as ⟨ next_begins, next_begins_post ⟩
        step as ⟨ next, next_post ⟩
        rw [bad2_post]
        have i_is : i.val = stop.val := by scalar_tac
        exact ⟨rfl, Or.inl (by omega), by omega⟩
      · rename_i not_end
        have below : i.val < stop.val := by
          have : i ≠ stop := not_end
          scalar_tac
        step as ⟨ x, x_post ⟩
        have x_at := bytes_at s i x (by omega) x_post
        split
        · rename_i is_slash
          have x_is : x.val = 47 := by rw [is_slash]; rfl
          rw [x_is] at x_at
          have at_boundary : i.val = begins.val + c.length := by
            by_contra not_boundary
            exact inside_c 47 (by omega) x_at rfl
          obtain ⟨r, after_is, more⟩ : ∃ r, after = 47 :: r ∧ PathRest r := by
            rcases kind with empty | found
            · rw [empty] at width; simp at width; omega
            · exact found
          have c_here : Component (Piece (Bytes s.val) begins i) := by
            rw [at_boundary, c_piece]; exact is_c
          step with component_bad_accepts_every_component s begins i begins_le (by omega)
            c_here as ⟨ bad2, bad2_post ⟩
          step as ⟨ next_begins, next_begins_post ⟩
          step as ⟨ next, next_post ⟩
          rw [bad2_post]
          have r_piece : Piece (Bytes s.val) (i.val + 1) stop = r := by
            have := piece_middle (Bytes s.val) begins stop (c ++ [47]) r []
              (by omega) (by simpa using inside) (by rw [cut, after_is]; simp)
            simp only [List.length_append, List.length_singleton] at this
            rw [after_is] at width
            simp at width
            rw [show begins.val + (c.length + 1) + r.length = stop.val by omega,
              ← Nat.add_assoc, ← at_boundary] at this
            simpa using this
          refine ⟨rfl, Or.inr ⟨?_, ?_, ?_, ?_⟩, by omega⟩
          · omega
          · omega
          · rw [next_begins_post, r_piece]; exact more
          · rw [next_post, next_begins_post, piece_empty]; simp
        · rename_i not_slash
          have short : i.val < begins.val + c.length := by
            by_contra not_short
            have at_boundary : i.val = begins.val + c.length := by omega
            rcases kind with empty | ⟨r, after_is, _⟩
            · rw [empty] at width; simp at width; omega
            · have slash_at : (Bytes s.val)[i.val]? = some 47 := by
                rw [at_boundary]
                exact piece_byte (Bytes s.val) begins stop c.length 47
                  (by rw [cut, after_is]; simp)
              rw [x_at] at slash_at
              exact not_slash (by rw [eq_says]; exact Option.some.inj slash_at)
          step as ⟨ next, next_post ⟩
          refine ⟨Or.inr ⟨begins_le.trans (by omega), by omega, rest, ?_⟩, by omega⟩
          rw [next_post, piece_snoc _ _ _ _ begins_le x_at]
          intro y y_in
          rcases List.mem_append.mp y_in with old | new
          · exact no_slash y old
          · rw [List.mem_singleton.mp new]
            exact inside_c x.val short x_at
    · simp only [WP.spec_ok]
  · exact ⟨rfl, Or.inr ⟨le_refl _, ordered, readable, by simp [piece_empty]⟩⟩

/-- `path_bad` finds nothing wrong only in a path of the grammar. -/
@[step] theorem path_bad_accepts_only_paths (s : Slice Std.U8) (start stop : Std.Usize)
    (ordered : start.val ≤ stop.val) (inside : stop.val ≤ s.length)
    (room : stop.val + 8 ≤ Usize.max) :
    path_bad s start stop ⦃ r => (r = none → Path (Piece (Bytes s.val) start stop)) ⦄ := by
  unfold path_bad
  exact path_loop_checks_the_components s start stop ordered inside room

/-- `path_bad` finds nothing wrong in every path of the grammar. -/
theorem path_bad_accepts_every_path (s : Slice Std.U8) (start stop : Std.Usize)
    (ordered : start.val ≤ stop.val) (inside : stop.val ≤ s.length)
    (room : stop.val + 8 ≤ Usize.max) (is_path : Path (Piece (Bytes s.val) start stop)) :
    path_bad s start stop ⦃ r => r = none ⦄ := by
  unfold path_bad
  exact path_loop_accepts_every_path s start stop ordered inside room
    (path_is_what_can_be_read is_path)

/-- `host_like` says `true` exactly when the piece has a `.` or a `:` or is `localhost`. -/
@[step] theorem host_like_says (s : Slice Std.U8) (start stop : Std.Usize)
    (ordered : start.val ≤ stop.val) (inside : stop.val ≤ s.length) :
    host_like s start stop ⦃ r => (r = true ↔ LooksLikeHost (Piece (Bytes s.val) start stop)) ⦄
        := by
  unfold host_like
  step as ⟨ dot, dot_after, dot_before, dot_none, dot_found ⟩
  split
  · rename_i has_dot
    simp only [WP.spec_ok, true_iff]
    exact Or.inl (piece_contains _ _ _ dot _ dot_after has_dot (dot_found has_dot))
  · rename_i no_dot
    have no_dot' : dot.val = stop.val := by scalar_tac
    step as ⟨ colon, colon_after, colon_before, colon_none, colon_found ⟩
    split
    · rename_i has_colon
      simp only [WP.spec_ok, true_iff]
      exact Or.inr (Or.inl (piece_contains _ _ _ colon _ colon_after has_colon
        (colon_found has_colon)))
    · rename_i no_colon
      have no_colon' : colon.val = stop.val := by scalar_tac
      step as ⟨ lit, lit_post ⟩
      step as ⟨ same, same_post ⟩
      have in_piece : ∀ x ∈ Piece (Bytes s.val) start stop, x ≠ 46 ∧ x ≠ 58 := by
        intro x x_in
        have as_dot : Piece (Bytes s.val) start stop = Piece (Bytes s.val) start dot := by
          rw [no_dot']
        have as_colon : Piece (Bytes s.val) start stop = Piece (Bytes s.val) start colon := by
          rw [no_colon']
        exact ⟨dot_none x (as_dot ▸ x_in), colon_none x (as_colon ▸ x_in)⟩
      rw [lit_post] at same_post
      constructor
      · intro is_it
        exact Or.inr (Or.inr (by simpa [Bytes, Ascii] using same_post.mp is_it))
      · rintro (has_dot | has_colon | is_it)
        · exact absurd rfl ((in_piece _ has_dot).1)
        · exact absurd rfl ((in_piece _ has_colon).2)
        · exact same_post.mpr (by simpa [Bytes, Ascii] using is_it)

end RefCore
